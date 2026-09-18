"""Task-scoped verifier: seed with the original package, probe and inspect upgrade."""
from __future__ import annotations
import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
import urllib.parse
import uuid

import base58
import jcs
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from anp.authentication.did_wba import compute_multikey_fingerprint
import awiki_open_server
from awiki_open_server.app.main import create_app
from awiki_open_server.app.settings import Settings
from awiki_open_server.service_identity import _sign_did_document, content_digest, service_identity_from_settings

DATA = Path('/var/lib/awiki-open-protocol-20260917')
UNIT = 'awiki-open-protocol-20260917.service'


def settings():
    return Settings(data_dir=DATA, public_base_url='https://rwiki.cn', did_domain='rwiki.cn',
        service_did='did:wba:rwiki.cn', service_private_key_pem=(DATA/'service-key.pem').read_text())


def stopped():
    state=subprocess.check_output(['systemctl','show',UNIT,'--property=ActiveState,MainPID'],text=True)
    assert 'ActiveState=inactive' in state and 'MainPID=0' in state


def inventory(group):
    with sqlite3.connect(f'file:{DATA}/awiki-open-server.sqlite3?mode=ro',uri=True) as conn:
        conn.row_factory=sqlite3.Row
        return [dict(row) for row in conn.execute('SELECT delivery_id,method,status,last_error,envelope_json FROM group_delivery_outbox WHERE group_did=? ORDER BY delivery_id',(group,))]


def hashes(rows):
    return {row['delivery_id']:hashlib.sha256(row['envelope_json'].encode()).hexdigest() for row in rows}


def proof(meta,body,key,method):
    digest=content_digest(jcs.canonicalize({'method':method,'meta':meta,'body':body}))
    now=int(time.time());kid=meta['sender_did']+'#key-1'
    sig_input=f'sig1=("@method" "@target-uri" "content-digest");created={now};expires={now+300};keyid="{kid}"'
    target=meta['target']
    value='\n'.join([f'"@method": {method}',f'"@target-uri": anp://{target["kind"]}/{urllib.parse.quote(target["did"],safe="-._~")}',
        f'"content-digest": {digest}',f'"@signature-params": {sig_input.split("=",1)[1]}']).encode()
    return {'contentDigest':digest,'signatureInput':sig_input,'signature':'sig1=:'+base64.b64encode(key.sign(value)).decode()+':'}


async def seed(peer, path):
    import httpx
    stopped()
    assert peer.startswith('did:wba:awiki.info:user:systestmd')
    assert 'baseline-deployment-venv' in awiki_open_server.__file__
    config=settings();app=create_app(config)
    root_key=ed25519.Ed25519PrivateKey.generate()
    handle='osprotoneg'+uuid.uuid4().hex[:12]
    did=f'did:wba:rwiki.cn:users:{handle}:e1_{compute_multikey_fingerprint(root_key.public_key())}'
    kid=did+'#key-1'
    multikey='z'+base58.b58encode(b'\xed\x01'+root_key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
    doc={'id':did,'verificationMethod':[{'id':kid,'type':'Multikey','controller':did,'publicKeyMultibase':multikey}],
        'authentication':[kid],'assertionMethod':[kid],'service':[{'id':did+'#message','type':'ANPMessageService',
        'serviceEndpoint':'https://rwiki.cn/anp-im/rpc','serviceDid':'did:wba:rwiki.cn',
        'profiles':['anp.direct.base.v1','anp.group.base.v1'],'securityProfiles':['transport-protected']}]}
    doc=_sign_did_document(doc,root_key,kid)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://rwiki.cn') as client:
        async def call(method,params,token=None):
            response=await client.post('/did-auth/rpc' if method=='register' else '/im/rpc',
                json={'jsonrpc':'2.0','id':'v1-backlog','method':method,'params':params},
                headers={'Authorization':'Bearer '+token} if token else {})
            value=response.json();assert 'result' in value,(method,value.get('error',{}).get('message'))
            return value['result']
        actor=await call('register',{'handle':handle,'did_document':doc})
        path.write_text(json.dumps({'owner_did':did,'owner_handle':handle,'target_did':peer,'stage':'owner_registered'})+'\n')
        async def group_call(method,target,body):
            operation=uuid.uuid4().hex
            meta={'profile':'anp.group.base.v1','security_profile':'transport-protected','sender_did':did,
                'target':{'kind':'service' if method=='group.create' else 'group','did':target},
                'operation_id':operation,'content_type':'application/json'}
            if method=='group.send':meta['message_id']='msg-'+operation
            return await call(method,{'meta':meta,'body':body,'auth':{'scheme':'anp-rfc9421-origin-proof-v1',
                'origin_proof':proof(meta,body,root_key,method)}},actor['token'])
        policy={'message_security_profile':'transport-protected','bootstrap_security_profile':'transport-protected',
            'admission_mode':'admin-add','permissions':{'send':'member','add':'admin','remove':'admin','update_profile':'admin','update_policy':'owner'},'max_members':'100'}
        group=(await group_call('group.create',config.service_did,{'group_profile':{'display_name':'v1 backlog rejection gate'},'group_policy':policy}))['group_did']
        path.write_text(json.dumps({'owner_did':did,'owner_handle':handle,'target_did':peer,'group_did':group,'stage':'group_created'})+'\n')
        await group_call('group.add',group,{'member_did':peer,'role':'member'})
        await group_call('group.send',group,{'payload':{'text':'original v1 backlog must not be rewritten'}})
    rows=inventory(group)
    assert len(rows)==2 and all(row['status']=='pending' for row in rows)
    evidence={'group_did':group,'owner_did':did,'owner_handle':handle,'target_did':peer,
        'original_package':awiki_open_server.__file__,'payload_sha256':hashes(rows)}
    path.write_text(json.dumps(evidence,indent=2)+'\n')
    print(json.dumps({'seeded':True,'delivery_count':len(rows)}))


def probe(path):
    import httpx
    assert 'baseline-deployment-venv' in awiki_open_server.__file__
    evidence=json.loads(path.read_text());config=settings()
    item=next(row for row in inventory(evidence['group_did']) if row['method']=='group.incoming')
    envelope=json.loads(item['envelope_json']);raw=json.dumps(envelope,ensure_ascii=False,separators=(',',':')).encode()
    endpoint='https://awiki.info/anp-im/rpc'
    headers={'Content-Type':'application/json','x-anp-source-service-did':config.service_did}
    signer=service_identity_from_settings(service_did=config.service_did,endpoint=config.public_base_url+'/anp-im/rpc',private_key_pem=config.service_private_key_pem)
    headers.update(signer.sign_headers(endpoint,'POST',headers,raw))
    response=httpx.post(endpoint,headers=headers,content=raw,trust_env=False,timeout=20)
    result={'notification_http_status':response.status_code,'notification_response_bytes':len(response.content)}
    # A notification has no RPC reply, including on a retired route. Probe the
    # originating mutation separately; its original business proof is retained.
    from awiki_open_server.messaging.groups.inbound import _INCOMING_CONTROL_FIELDS
    params=envelope['params'];group=evidence['group_did']
    request={'jsonrpc':'2.0','id':'retired-v1-mutation-probe','method':'group.send','params':{
        'meta':{**params['meta'],'target':{'kind':'group','did':group}},
        'body':{key:value for key,value in params['body'].items() if key not in _INCOMING_CONTROL_FIELDS},
        'auth':params['auth']}}
    raw=json.dumps(request,ensure_ascii=False,separators=(',',':')).encode()
    headers={'Content-Type':'application/json','x-anp-source-service-did':config.service_did}
    headers.update(signer.sign_headers(endpoint,'POST',headers,raw))
    mutation=httpx.post(endpoint,headers=headers,content=raw,trust_env=False,timeout=20)
    value=mutation.json();error=value.get('error') or {}
    result.update(mutation_http_status=mutation.status_code,rpc_code=error.get('code'),anp_code=(error.get('data') or {}).get('anp_code'))
    path.with_name('commercial-v1-rejection.json').write_text(json.dumps(result,indent=2)+'\n')
    assert result['notification_http_status']==400,result
    assert error.get('code')==-32601,result
    print(json.dumps(result))


def verify_blocked(path):
    stopped()
    assert 'baseline-deployment-venv' not in awiki_open_server.__file__
    from awiki_open_server.messaging.groups.migration import inspect_group,prepare_group,apply_group,cancel_group
    from awiki_open_server.shared.errors import Conflict
    evidence=json.loads(path.read_text());config=settings();create_app(config)
    group=evidence['group_did'];rows=inventory(group)
    assert hashes(rows)==evidence['payload_sha256']
    assert any(row['status']=='dead' and 'peer_profile_not_supported' in (row['last_error'] or '') for row in rows)
    assert all(row['status']!='delivered' for row in rows)
    plan=inspect_group(config,group)
    prepare_group(config,group,plan['plan_digest'],path.parent/'migration-backup')
    try: apply_group(config,group,plan['plan_digest'])
    except Conflict as exc: assert str(exc)=='group.migration_outbox_not_drained'
    else: raise AssertionError('unresolved original v1 delivery must block migration')
    assert inspect_group(config,group)['wire_profile']=='anp.group.base.v1'
    cancel_group(config,group,plan['plan_digest'])
    assert hashes(inventory(group))==evidence['payload_sha256']
    result={'migration_blocked':True,'wire_profile':'anp.group.base.v1','payload_unchanged':True,
        'delivery_statuses':[row['status'] for row in rows]}
    path.with_name('migration-blocked.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))


if __name__=='__main__':
    os.umask(0o077)
    mode=sys.argv[1];path=Path(sys.argv[2]).resolve()
    assert path.is_relative_to(Path('/home/ecs-user/awiki-space/verification-runs'))
    if mode=='seed':asyncio.run(seed(sys.argv[3],path))
    elif mode=='probe':probe(path)
    elif mode=='verify-blocked':verify_blocked(path)
    else:raise SystemExit('unknown mode')
