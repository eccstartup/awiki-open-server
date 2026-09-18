"""Send real signed plaintext requests from the separate Web DID test peer."""
import json
from pathlib import Path
import sys
import uuid
import httpx
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from awiki_open_server.service_identity import ServiceIdentity
from tests.helpers import origin_proof

root=Path('/var/lib/awiki-open-protocol-20260917/web-peer-20260918')
config=json.loads((root/'public-config.json').read_text())
kind,target,text=sys.argv[1:]
assert kind in {'direct','group'} and target.startswith('did:wba:rwiki.cn:')
method=kind+'.send';operation=uuid.uuid4().hex
meta={'profile':'anp.direct.base.v1' if kind=='direct' else 'anp.group.base.v2',
    'security_profile':'transport-protected','sender_did':config['actor_did'],
    'target':{'kind':'agent' if kind=='direct' else 'group','did':target},
    'operation_id':operation,'message_id':'msg-'+operation,'content_type':'text/plain'}
body={'text':text}
key=load_pem_private_key((root/'actor-key.pem').read_bytes(),password=None)
params={'meta':meta,'body':body,'auth':{'scheme':'anp-rfc9421-origin-proof-v1',
    'origin_proof':origin_proof(meta,body,key,method=method)}}
request={'jsonrpc':'2.0','id':operation,'method':method,'params':params}
raw=json.dumps(request,ensure_ascii=False,separators=(',',':')).encode()
home=config['home_did'];signer=ServiceIdentity(home,config['home_document'],(root/'home-key.pem').read_text(),home+'#key-1')
url='https://rwiki.cn/anp-im/rpc'
headers={'Content-Type':'application/json','x-anp-source-service-did':home}
headers.update(signer.sign_headers(url,'POST',headers,raw))
response=httpx.post(url,content=raw,headers=headers,trust_env=False,timeout=20)
value=response.json()
if 'result' not in value:
    error=value.get('error') or {}
    print(json.dumps({'ok':False,'http_status':response.status_code,'code':error.get('code'),
        'message':error.get('message'),'anp_code':(error.get('data') or {}).get('anp_code')}))
    raise SystemExit(1)
result=value['result']
assert result.get('accepted') is True
print(json.dumps({'ok':True,'message_id':meta['message_id'],'sender_did':config['actor_did']}))
