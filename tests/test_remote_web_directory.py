from __future__ import annotations
import copy
from types import SimpleNamespace
import pytest
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from awiki_open_server.app.settings import Settings
from awiki_open_server.protocol.anp_adapter import AnpProtocolError, web_handle_hint, verify_web_handle_documents
from awiki_open_server.service_identity import _sign_did_document
from awiki_open_server.shared import runtime
from awiki_open_server.user_compat.core import handle_lookup, _validate_local_user_did
from awiki_open_server.shared.errors import InvalidParams
from awiki_open_server.storage.db import Store
from tests.fixtures.web_did_peer import prepare


def material(tmp_path):
    root=tmp_path/'peer';config=prepare(root,'/protocol-peer-directory')
    did=config['actor_did'];doc=config['actor_document']
    doc['service']=[entry for entry in doc['service'] if entry['type']!='ANPHandleService']
    doc['service'].append({'id':did+'#handle','type':'ANPHandleService','serviceEndpoint':'https://rwiki.cn/.well-known/handle/webpeer'})
    doc=_sign_did_document(doc,load_pem_private_key((root/'actor-key.pem').read_bytes(),password=None),did+'#key-1')
    return doc, {'handle':'webpeer.rwiki.cn','did':did,'status':'active','binding_generation':'1'}


def test_web_directory_requires_two_way_binding_and_keeps_ownership_remote(tmp_path,monkeypatch):
    doc,binding=material(tmp_path)
    settings=Settings(data_dir=tmp_path/'data',did_domain='rwiki.cn',service_did='did:wba:rwiki.cn',public_base_url='https://rwiki.cn')
    store=Store(settings.db_path,settings.did_domain)
    request=SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(store=store,settings=settings)))
    monkeypatch.setattr(runtime,'_fetch_did_document',lambda did,_settings: copy.deepcopy(doc))
    requested=[]
    def fetch(url,**options):
        requested.append((url,options));return copy.deepcopy(binding)
    monkeypatch.setattr(runtime,'_http_get_json',fetch)
    result=handle_lookup({'did':doc['id']},request)
    assert result['did']==doc['id'] and result['full_handle']==binding['handle']
    assert result['binding_generation']=='1'
    assert requested==[('https://rwiki.cn/.well-known/handle/webpeer',{})]
    with store.connect() as conn:
        assert conn.execute('SELECT count(*) FROM users WHERE did=?',(doc['id'],)).fetchone()[0]==0
    with pytest.raises(InvalidParams,match='valid_did_required'):
        _validate_local_user_did(doc['id'],settings)
    binding['did']='did:web:other.example:actor'
    with pytest.raises(InvalidParams,match='web_handle_binding_invalid'):
        handle_lookup({'did':doc['id']},request)


def test_web_binding_rejects_inactive_retargeted_or_missing_reverse_declarations(tmp_path):
    doc,binding=material(tmp_path)
    assert web_handle_hint(doc)=='webpeer.rwiki.cn'
    for field,value in [('status','revoked'),('handle','other.rwiki.cn'),('did','did:web:other.example:actor'),('binding_generation','01')]:
        with pytest.raises(AnpProtocolError,match='web_handle_binding_invalid'):
            verify_web_handle_documents('webpeer.rwiki.cn',{**binding,field:value},doc)
    wrong=copy.deepcopy(doc);wrong['service']=wrong['service'][:1]
    key=load_pem_private_key((tmp_path/'peer/actor-key.pem').read_bytes(),password=None)
    wrong=_sign_did_document(wrong,key,doc['id']+'#key-1')
    with pytest.raises(AnpProtocolError):verify_web_handle_documents('webpeer.rwiki.cn',binding,wrong)
    domain_only=copy.deepcopy(doc)
    domain_only['service'][-1]['serviceEndpoint']='https://rwiki.cn/stable-handle-provider'
    domain_only=_sign_did_document(domain_only,key,doc['id']+'#key-1')
    assert verify_web_handle_documents('webpeer.rwiki.cn',binding,domain_only).did==doc['id']
    assert web_handle_hint(domain_only) is None
    domain_only['service'][-1]['serviceEndpoint']='https://other.example/stable-handle-provider'
    domain_only=_sign_did_document(domain_only,key,doc['id']+'#key-1')
    with pytest.raises(AnpProtocolError):verify_web_handle_documents('webpeer.rwiki.cn',binding,domain_only)


def test_native_web_binding_does_not_require_wba_fingerprint_or_document_proof(tmp_path):
    import json
    doc,binding=material(tmp_path)
    old=doc['id'];did='did:web:external.example:e1_not_a_wba_fingerprint'
    doc=json.loads(json.dumps(doc).replace(old,did));doc.pop('proof')
    binding={**binding,'did':did}
    assert verify_web_handle_documents('webpeer.rwiki.cn',binding,doc).did==did
