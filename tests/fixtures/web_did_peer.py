"""Temporary public protocol peer for remote did:web interoperability gates.

This is a separate verification peer, not local Web identity registration.
Only the explicitly selected Open Home can send to its generated test identity.
"""
from __future__ import annotations
import json
import hashlib
import asyncio
import os
import re
from pathlib import Path
import urllib.parse
import urllib.request
import base58

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from awiki_open_server.protocol.anp_adapter import did_resolution_url, require_did_document_binding, verify_group_receipt
from awiki_open_server.service_identity import verify_peer_http_signature, validate_origin_proof_structure
from awiki_open_server.service_identity import generate_ed25519_private_key_pem, _sign_did_document
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PublicFormat
from awiki_open_server.messaging.groups.inbound import _INCOMING_CONTROL_FIELDS, verified_acceptance_time
from awiki_open_server.shared.ids import now_iso

PROFILES = ['anp.core.binding.v1','anp.identity.discovery.v1','anp.direct.base.v1','anp.group.base.v2']


def prepare(root: Path, prefix: str):
    assert re.fullmatch(r'/protocol-peer-[a-z0-9]{1,40}', prefix)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    if any((root/name).exists() for name in ['public-config.json','home-key.pem','actor-key.pem']):
        raise FileExistsError('preserve the existing verification peer identity')
    config={'prefix':prefix,'home_did':'did:web:rwiki.cn:'+prefix[1:]+':home',
        'actor_did':'did:web:rwiki.cn:'+prefix[1:]+':actor'}
    config['handle_local']='w'+hashlib.sha256(config['actor_did'].encode()).hexdigest()[:15]
    config['handle_document']={'handle':config['handle_local']+'.rwiki.cn','did':config['actor_did'],
        'status':'active','binding_generation':'1'}
    endpoint='https://rwiki.cn'+prefix+'/anp-im/rpc'
    for kind in ['home','actor']:
        pem=generate_ed25519_private_key_pem()
        key=load_pem_private_key(pem.encode(),password=None)
        did=config[kind+'_did']
        kid=did+'#key-1'
        public='z'+base58.b58encode(b'\xed\x01'+key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
        doc={'@context':['https://www.w3.org/ns/did/v1'],'id':did,
            'verificationMethod':[{'id':kid,'type':'Multikey','controller':did,'publicKeyMultibase':public}],
            'authentication':[kid],'assertionMethod':[kid],
            'service':[{'id':did+'#message','type':'ANPMessageService','serviceDid':config['home_did'],
                'serviceEndpoint':endpoint,'profiles':PROFILES,'securityProfiles':['transport-protected']}]}
        if kind=='actor':
            doc['service'].append({'id':did+'#handle','type':'ANPHandleService',
                'serviceEndpoint':'https://rwiki.cn/.well-known/handle/'+config['handle_local']})
        doc=_sign_did_document(doc,key,did+'#key-1')
        require_did_document_binding(doc)
        config[kind+'_document']=doc
        private=root/(kind+'-key.pem')
        private.write_text(pem);private.chmod(0o600)
    (root/'public-config.json').write_text(json.dumps(config,indent=2)+'\n')
    return config


def create_app():
    root=Path(os.environ['AWIKI_WEB_PEER_STATE']).resolve()
    config=json.loads((root/'public-config.json').read_text())
    prefix=config['prefix']
    assert re.fullmatch(r'/protocol-peer-[a-z0-9]{1,40}', prefix)
    app=FastAPI()
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def fetch_document(did):
        url=did_resolution_url(did)
        parsed=urllib.parse.urlsplit(url)
        if parsed.scheme!='https' or parsed.netloc!='rwiki.cn':
            raise ValueError('fixture only resolves its selected public authority')
        with opener.open(url,timeout=15) as response:
            raw=response.read(1024*1024+1)
        if len(raw)>1024*1024:raise ValueError('document limit')
        value=json.loads(raw)
        if value.get('id')!=did:raise ValueError('document identity mismatch')
        require_did_document_binding(value)
        return value

    async def document(did):
        # A sender echo may resolve our own public DID URL. Keep the ASGI loop
        # available to answer that HTTPS request while verifying the callback.
        return await asyncio.to_thread(fetch_document,did)

    @app.get(prefix+'/home/did.json')
    def home():return config['home_document']

    @app.get(prefix+'/actor/did.json')
    def actor():return config['actor_document']

    @app.get('/.well-known/handle/'+config['handle_local'])
    def handle():return config['handle_document']

    @app.get(prefix+'/healthz')
    def health():return {'status':'ok','purpose':'public Web DID verification peer'}

    @app.post(prefix+'/anp-im/rpc')
    async def rpc(request: Request):
        raw=await request.body()
        if len(raw)>1024*1024:return Response(status_code=413)
        value=json.loads(raw);method=value.get('method');params=value.get('params') or {}
        if method=='anp.get_capabilities':
            return {'jsonrpc':'2.0','id':value.get('id'),'result':{
                'service_did':config['home_did'],'profiles':PROFILES,'supported_profiles':PROFILES,
                'security_profiles':['transport-protected'],
                'methods':['anp.get_capabilities','direct.send','group.incoming','group.state_changed']}}
        if method not in {'direct.send','group.incoming','group.state_changed'}:
            return JSONResponse({'jsonrpc':'2.0','id':value.get('id'),'error':{'code':-32601,'message':'unsupported fixture method'}},status_code=400)
        stage='source_signature'
        try:
            source=request.headers.get('x-anp-source-service-did')
            if source!='did:wba:rwiki.cn':raise ValueError('unexpected source Home')
            verify_peer_http_signature(service_did_document=await document(source),method='POST',
                url='https://rwiki.cn'+prefix+'/anp-im/rpc',headers=dict(request.headers),body=raw)
            stage='business_proof'
            meta=params['meta'];body=params['body'];auth=params.get('auth')
            if meta.get('target',{}).get('did')!=config['actor_did']:raise ValueError('wrong recipient')
            if meta.get('security_profile')!='transport-protected':raise ValueError('wrong security profile')
            if method=='direct.send':
                if meta.get('profile')!='anp.direct.base.v1':raise ValueError('wrong direct profile')
                validate_origin_proof_structure(auth,method=method,meta=meta,body=body,sender_did_document=await document(meta['sender_did']))
            else:
                if meta.get('profile')!='anp.group.base.v2':raise ValueError('wrong group profile')
                group=body['group_did'];receipt=body['group_receipt']
                if not verify_group_receipt(receipt,issuer_did_document=await document(group)):raise ValueError('invalid Receipt')
                if receipt['group_did']!=group or receipt['group_event_seq']!=body['group_event_seq'] or receipt['group_state_version']!=body['group_state_version']:
                    raise ValueError('Receipt binding mismatch')
                if receipt.get('subject_method') != ('group.send' if method=='group.incoming' else body.get('subject_method')):
                    raise ValueError('Receipt method mismatch')
                if method=='group.incoming':
                    if receipt.get('message_id')!=meta.get('message_id') or receipt.get('actor_did')!=meta.get('sender_did'):
                        raise ValueError('message Receipt binding mismatch')
                    original_meta={**meta,'target':{'kind':'group','did':group}}
                    original_body={key:item for key,item in body.items() if key not in _INCOMING_CONTROL_FIELDS}
                    if receipt.get('payload_digest')!=(auth or {}).get('origin_proof',{}).get('contentDigest'):
                        raise ValueError('origin digest binding mismatch')
                    validate_origin_proof_structure(auth,method='group.send',meta=original_meta,body=original_body,
                        sender_did_document=await document(meta['sender_did']),verified_at=verified_acceptance_time(receipt,body))
        except Exception as exc:
            with (root/'rejected.jsonl').open('a') as stream:
                stream.write(json.dumps({'stage':stage,'error_type':type(exc).__name__,'method':method})+'\n')
            return Response(status_code=401)
        record={'method':method,'message_id':meta.get('message_id'),'group_did':body.get('group_did'),
            'sender_did':meta.get('sender_did'),'group_event_seq':body.get('group_event_seq'),'verified':True}
        with (root/'received.jsonl').open('a') as stream:stream.write(json.dumps(record)+'\n')
        if method!='direct.send':return Response(status_code=204)
        return {'jsonrpc':'2.0','id':value.get('id'),'result':{'accepted':True,'final_acceptance':True,
            'delivery_state':'accepted','message_id':meta['message_id'],'operation_id':meta['operation_id'],
            'target_did':config['actor_did'],'accepted_at':now_iso()}}
    return app
