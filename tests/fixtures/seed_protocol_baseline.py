"""Run only against an immutable original source archive in a child process.

All state is created through that version's RPCs; output contains test credentials
and is written only into the caller's private temporary directory.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import inspect
import json
import os
from pathlib import Path
import sys

import httpx
from anp.authentication.did_wba import compute_multikey_fingerprint
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from awiki_open_server.app.main import create_app
from awiki_open_server.app.settings import Settings
from awiki_open_server.service_identity import generate_ed25519_private_key_pem
from tests.helpers import did_keypair_document, sign_did_document, origin_proof
from tests.test_group_host import _group_envelope


async def seed(root: Path):
    expected = Path(os.environ['AWIKI_EXPECT_BASELINE_PACKAGE']).resolve()
    assert Path(inspect.getfile(create_app)).resolve().is_relative_to(expected)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    service_key = generate_ed25519_private_key_pem()
    (root / 'service-key.pem').write_text(service_key)
    domain = os.environ.get('AWIKI_BASELINE_DOMAIN', 'testserver')
    base_url = os.environ.get('AWIKI_BASELINE_BASE_URL', 'http://testserver')
    settings = Settings(data_dir=root / 'data', public_base_url=base_url,
                        did_domain=domain, service_did=f'did:wba:{domain}',
                        service_private_key_pem=service_key, allow_unsigned_peer_dev=True)
    app = create_app(settings)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://testserver') as client:
        async def call(method, params, token=None):
            response = await client.post('/im/rpc' if method != 'register' else '/did-auth/rpc',
                json={'jsonrpc':'2.0', 'id':'baseline', 'method':method, 'params':params},
                headers={'Authorization':f'Bearer {token}'} if token else {})
            assert response.status_code == 200, method
            value = response.json()
            assert 'result' in value, (method, value.get('error', {}).get('message'))
            return value['result']

        identities = []
        for handle in ['baseline-owner', 'baseline-member']:
            placeholder = f'did:wba:{domain}:users:{handle}:e1_pending'
            key, doc = did_keypair_document(placeholder)
            did = placeholder.rsplit(':', 1)[0] + ':e1_' + compute_multikey_fingerprint(key.public_key())
            doc = json.loads(json.dumps(doc).replace(placeholder, did))
            doc['service'][0]['serviceEndpoint'] = base_url + '/anp-im/rpc'
            doc['service'][0]['serviceDid'] = settings.service_did
            # The old helper declares only Direct/Group. This fixture also
            # publishes attachments, so advertise that existing v1 capability
            # before the original document is signed and registered.
            doc['service'][0]['profiles'].append('anp.attachment.v1')
            doc = sign_did_document(doc, key)
            registered = await call('register', {'handle':handle, 'did_document':doc})
            key_path = root / f'{handle}.pem'
            key_path.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
            identities.append({'did':did, 'token':registered['token'], 'key':key, 'document':doc,
                               'user_id':registered.get('user_id', did), 'handle':handle})
        owner, member = identities
        async def group(method, actor, target, operation, body):
            envelope = _group_envelope(method=method, sender_did=actor['did'], target_did=target,
                operation_id=operation, body=body, private_key=actor['key'],
                target_kind='service' if method == 'group.create' else 'group')
            return await call(method, envelope, actor['token'])
        policy = {'message_security_profile':'transport-protected', 'bootstrap_security_profile':'transport-protected',
                  'admission_mode':'open-join', 'permissions':{'send':'member', 'add':'admin', 'remove':'admin',
                  'update_profile':'admin', 'update_policy':'owner'}, 'max_members':'100'}
        created = await group('group.create', owner, settings.service_did, 'baseline-create',
                              {'group_profile':{'display_name':'Original version group'}, 'group_policy':policy})
        group_did = created['group_did']
        await group('group.join', member, group_did, 'baseline-join', {})
        messages = []
        for index in range(3):
            messages.append(await group('group.send', owner, group_did, f'baseline-message-{index}', {'text':f'old message {index}'}))
        direct = await call('direct.send', {'to':member['did'], 'text':'old direct message'}, owner['token'])
        read = await call('read_state.mark_read', {'body':{'user_did':member['did'],
            'thread':{'kind':'direct', 'peer_did':owner['did']}, 'read_up_to_message_id':direct['message_id']}}, member['token'])
        slot = await call('attachment.create_slot', {}, owner['token'])
        data = b'original-version attachment\x00\xff'
        uploaded = await client.put('/objects/upload/' + slot['slot_id'], params={'token':slot['upload_token']}, content=data)
        assert uploaded.status_code == 200
        committed = await call('attachment.commit_object', {'slot_id':slot['slot_id'], 'commit_token':slot['commit_token'], 'content_type':'application/octet-stream'}, owner['token'])
        attachment_meta = {'profile':'anp.direct.base.v1', 'security_profile':'transport-protected',
            'sender_did':owner['did'], 'target':{'kind':'agent','did':member['did']},
            'operation_id':'baseline-attachment', 'message_id':'baseline-attachment-message',
            'content_type':'application/anp-attachment-manifest+json'}
        attachment_body = {'payload':{'attachments':[{'attachment_id':slot['attachment_id'],
            'filename':'original.bin', 'mime_type':'application/octet-stream', 'size':str(len(data)),
            'digest':{'alg':'sha-256','value_b64u':base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode()},
            'access_info':{'object_uri':committed['object_uri']}, 'encryption_info':{'mode':'none'}}],
            'primary_attachment_id':slot['attachment_id']}}
        attachment_message = await call('direct.send', {'meta':attachment_meta, 'body':attachment_body,
            'auth':{'scheme':'anp-rfc9421-origin-proof-v1', 'origin_proof':origin_proof(attachment_meta,attachment_body,owner['key'])}},owner['token'])
        report = {'group_did':group_did, 'messages':messages, 'direct':direct, 'read':read,
                  'attachment_message_id':attachment_message['message_id'],
                  'object_id':committed['object_id'], 'attachment_sha256':hashlib.sha256(data).hexdigest(),
                  'identities':[{k:v for k,v in item.items() if k != 'key'} for item in identities]}
        (root / 'seed.json').write_text(json.dumps(report))
    for file in root.rglob('*'):
        if file.is_file(): file.chmod(0o600)


if __name__ == '__main__':
    os.umask(0o077)
    asyncio.run(seed(Path(sys.argv[1])))
