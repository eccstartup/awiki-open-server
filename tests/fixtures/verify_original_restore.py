"""Verify a restored complete backup with the unchanged original package."""
import asyncio,json,os
from pathlib import Path
import sys
import httpx
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from anp.proof import verify_group_receipt_proof
from awiki_open_server.app.main import create_app
from awiki_open_server.app.settings import Settings
from tests.test_group_host import _group_rpc

async def run(root):
    seed=json.loads((root/'seed.json').read_text());owner=seed['identities'][0]
    app=create_app(Settings(data_dir=root/'data',public_base_url='http://testserver',did_domain='testserver',
        service_did='did:wba:testserver',service_private_key_pem=(root/'service-key.pem').read_text(),allow_unsigned_peer_dev=True))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://testserver') as client:
        result=await _group_rpc(client,method='group.send',sender_did=owner['did'],token=owner['token'],
            private_key=load_pem_private_key((root/'baseline-owner.pem').read_bytes(),password=None),
            target_did=seed['group_did'],operation_id='after-original-restore',body={'text':'old binary continued after full restore'})
        assert 'result' in result
        assert int(result['result']['group_event_seq'])==int(seed['messages'][-1]['group_event_seq'])+1
        doc=(await client.get('/'+seed['group_did'][len('did:wba:testserver:'):].replace(':','/')+'/did.json')).json()
        assert verify_group_receipt_proof(result['result']['group_receipt'],doc)
        with app.state.store.connect() as conn:
            assert 'wire_profile' not in {row[1] for row in conn.execute('PRAGMA table_info(hosted_groups)')}
    print(json.dumps({'original_binary_restored':True,'new_v1_send_verified':True}))

if __name__=='__main__':
    os.umask(0o077)
    asyncio.run(run(Path(sys.argv[1]).resolve()))
