"""Actual signature checks after transport authentication, including old acceptance."""
import copy
from datetime import datetime,timezone,timedelta
import time
from types import SimpleNamespace
import pytest
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from awiki_open_server.app.settings import Settings
from awiki_open_server.messaging.groups import inbound
from awiki_open_server.messaging.groups.identity import generate_group_identity
from awiki_open_server.protocol.anp_adapter import sign_group_receipt
from awiki_open_server.service_identity import validate_origin_proof_structure
from awiki_open_server.shared.errors import InvalidParams,Unauthorized
from awiki_open_server.storage.db import Store
from tests.helpers import bound_did_keypair_document,sign_did_document,origin_proof


@pytest.mark.parametrize('profile',['anp.group.base.v1','anp.group.base.v2'])
def test_delayed_accepted_origin_keeps_original_signature_and_new_requests_stay_expired(tmp_path,monkeypatch,profile):
    owner='did:wba:home.test:users:member'
    group_doc,pem=generate_group_identity(hostname='host.test',group_id='delayed',service_endpoint='https://host.test/anp-im/rpc',service_did='did:wba:host.test',profile=profile)
    group=group_doc['id'];group_key=load_pem_private_key(pem.encode(),password=None)
    sender_key,sender_doc=bound_did_keypair_document('did:wba:sender.test:user:sender:e1_pending')
    sender_doc=sign_did_document(sender_doc,sender_key);sender=sender_doc['id']
    created=int(time.time())-3600
    accepted=datetime.fromtimestamp(created+1,timezone.utc).isoformat()
    meta={'profile':profile,'security_profile':'transport-protected','sender_did':sender,
        'target':{'kind':'group','did':group},'operation_id':'old-operation','message_id':'old-message','content_type':'text/plain'}
    body={'text':'accepted before offline period'}
    auth={'scheme':'anp-rfc9421-origin-proof-v1','origin_proof':origin_proof(meta,body,sender_key,method='group.send',created=created)}
    original=copy.deepcopy(auth)
    def receipt(**changes):
        value={'receipt_type':'group-message-accepted','group_did':group,'group_state_version':'1','group_event_seq':'2',
            'subject_method':'group.send','operation_id':'old-operation','message_id':'old-message','actor_did':sender,
            'accepted_at':accepted,'payload_digest':auth['origin_proof']['contentDigest'],**changes}
        return sign_group_receipt(value,private_key=group_key,verification_method=group+'#key-1')
    message={'meta':{**meta,'target':{'kind':'agent','did':owner}},'_anp_auth':auth,
        'body':{**body,'group_did':group,'group_state_version':'1','group_event_seq':'2','accepted_at':accepted,'group_receipt':receipt()}}
    store=Store(tmp_path/'state.sqlite3','home.test')
    settings=Settings(data_dir=tmp_path,public_base_url='https://home.test',did_domain='home.test',service_did='did:wba:home.test')
    request=SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(store=store,settings=settings)),state=SimpleNamespace(peer_service_did='did:wba:host.test'))
    with store.connect() as conn:
        conn.execute("INSERT INTO group_views(owner_did,group_did,host_service_did,profile_json,policy_json,group_state_version,group_event_seq,member_role,membership_status,updated_at,wire_profile) VALUES (?,?,?,'{}','{}',1,1,'member','active',?,'anp.group.base.v2')",(owner,group,'did:wba:host.test',accepted))
    monkeypatch.setattr(inbound,'_notification_context',lambda params,*_: (params['meta'],params['body'],owner,group))
    monkeypatch.setattr(inbound.runtime,'_resolve_did_document_for_proof',lambda _request,did: group_doc if did==group else sender_doc)
    monkeypatch.setattr(inbound.runtime,'_publish_realtime',lambda *_,**__:None)
    with pytest.raises(Unauthorized,match='signature_expired'):
        validate_origin_proof_structure(auth,method='group.send',meta=meta,body=body,sender_did_document=sender_doc)
    assert inbound.group_incoming(message,request)['accepted'] is True
    assert inbound.group_incoming(message,request)['duplicate'] is True
    assert auth==original
    for changes in [{'actor_did':owner},{'operation_id':'other-operation'},
                    {'accepted_at':datetime.now(timezone.utc).isoformat()},
                    {'accepted_at':(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat()}]:
        invalid=copy.deepcopy(message);invalid['body']['group_receipt']=receipt(**changes)
        if 'accepted_at' in changes:invalid['body']['accepted_at']=changes['accepted_at']
        with pytest.raises((InvalidParams,Unauthorized)):
            inbound.group_incoming(invalid,request)
    invalid=copy.deepcopy(message);invalid['body']['accepted_at']=datetime.now(timezone.utc).isoformat()
    with pytest.raises(InvalidParams):inbound.group_incoming(invalid,request)
    invalid=copy.deepcopy(message)
    value=invalid['body']['group_receipt']['proof']['proofValue']
    invalid['body']['group_receipt']['proof']['proofValue']=value[:-1]+('1' if value[-1]!='1' else '2')
    with pytest.raises(InvalidParams):inbound.group_incoming(invalid,request)
    with store.connect() as conn:
        assert conn.execute('SELECT count(*) FROM group_message_views').fetchone()[0]==1
        assert conn.execute('SELECT count(*) FROM inbound_peer_events').fetchone()[0]==1
