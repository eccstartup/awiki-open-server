"""Real original-version v1 backlog, signed delivery and controlled cutover."""
from __future__ import annotations
import hashlib
import json
import os
import re
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
import uuid
from contextlib import asynccontextmanager

import httpx
from awiki_open_server.app.main import create_app
from awiki_open_server.app.settings import Settings
from awiki_open_server.messaging.groups.migration import inspect_group, prepare_group, apply_group
from awiki_open_server.messaging.groups.outbox import drain_group_outbox_once
from awiki_open_server.service_identity import generate_ed25519_private_key_pem, service_identity_from_settings
from awiki_open_server.shared import runtime
from scripts.awiki_open_cli import generate_test_tls_material, stop_process, wait_health
from tests.helpers import bound_did_keypair_document, sign_did_document, origin_proof
from tests.test_original_version_upgrade import extract_original_version, BASELINE


@asynccontextmanager
async def paused_delivery_lifespan(_app):
    yield


def create_paused_delivery_app():
    """Keep real RPC handlers; the test schedules the real worker explicitly."""
    app = create_app()
    app.router.lifespan_context = paused_delivery_lifespan
    return app


def rows(path, sql, values=()):
    with sqlite3.connect(f'file:{path}?mode=ro', uri=True) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute(sql, values)]


def until(check, label, seconds=35):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if check(): return
        time.sleep(.1)
    raise AssertionError(label)


def run(root: Path):
    repo = Path(__file__).resolve().parents[2]
    original, archive = extract_original_version(root)
    domains = ['outbox-host.test','outbox-peer.test']
    bases = {domain:'https://' + domain for domain in domains}
    ca, cert, key = generate_test_tls_material(root, domains)
    os.environ['SSL_CERT_FILE'] = str(ca)
    os.environ['NO_PROXY'] = os.environ['no_proxy'] = '*'
    for name in ['HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy']:
        os.environ.pop(name,None)
    settings = [Settings(data_dir=root/domain, public_base_url=bases[domain], did_domain=domain,
        service_did='did:wba:'+domain, service_private_key_pem=generate_ed25519_private_key_pem(),
        did_resolver_base_urls=bases) for domain in domains]
    processes = [None,None]
    client = httpx.Client(verify=str(ca), trust_env=False, timeout=15)
    long_delay = os.environ.get('AWIKI_TEST_LONG_DELAY') == '1'
    def start(index, *, upgraded=False, paused_delivery=False):
        config=settings[index]
        source=repo if upgraded else original
        env={**os.environ,'PYTHONPATH':str(source/'src')+os.pathsep+str(source), 'AWIKI_DATA_DIR':str(config.data_dir),
            'AWIKI_PUBLIC_BASE_URL':config.public_base_url,'AWIKI_DID_DOMAIN':config.did_domain,
            'AWIKI_SERVICE_DID':config.service_did,'AWIKI_SERVICE_PRIVATE_KEY_PEM':config.service_private_key_pem.replace('\n','\\n'),
            'AWIKI_DID_RESOLVER_BASE_URLS':json.dumps(bases),'AWIKI_ALLOW_UNSIGNED_PEER_DEV':'0'}
        factory='tests.fixtures.run_original_outbox:create_paused_delivery_app' if paused_delivery else 'awiki_open_server.app.main:create_app'
        process=subprocess.Popen([sys.executable,'-m','uvicorn',factory,'--factory',
            '--host',f'127.0.0.{index+1}','--port','443','--ssl-certfile',str(cert),'--ssl-keyfile',str(key),'--log-level','error'],
            cwd=source,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
        processes[index]=process
        wait_health(config.public_base_url, process)
    def stop(index):
        if processes[index] is not None: stop_process(processes[index]);processes[index]=None
    def rpc(index, method, params, token=None):
        response=client.post(settings[index].public_base_url+('/did-auth/rpc' if method=='register' else '/im/rpc'),
            json={'jsonrpc':'2.0','id':'outbox-gate','method':method,'params':params},
            headers={'Authorization':'Bearer '+token} if token else {})
        assert response.status_code==200, (method,response.status_code)
        data=response.json()
        assert 'result' in data,(method,data.get('error',{}).get('message'))
        return data['result']
    def register(index, handle):
        config=settings[index]
        signing,doc=bound_did_keypair_document(f'did:wba:{config.did_domain}:users:{handle}:e1_pending')
        doc['service'][0].update(serviceEndpoint=config.public_base_url+'/anp-im/rpc',serviceDid=config.service_did,
            profiles=['anp.direct.base.v1','anp.group.base.v1','anp.attachment.v1'])
        doc=sign_did_document(doc,signing)
        registered=rpc(index,'register',{'handle':handle,'did_document':doc})
        return {'did':registered['did'],'token':registered['token'],'key':signing}
    def group_rpc(method, actor, target, body, profile='anp.group.base.v1', index=0):
        operation=uuid.uuid4().hex
        meta={'profile':profile,'security_profile':'transport-protected','sender_did':actor['did'],
            'target':{'kind':'service' if method=='group.create' else 'group','did':target},
            'operation_id':operation,'content_type':'application/json'}
        if method=='group.send': meta['message_id']='msg-'+operation
        return rpc(index,method,{'meta':meta,'body':body,'auth':{'scheme':'anp-rfc9421-origin-proof-v1',
            'origin_proof':origin_proof(meta,body,actor['key'],method=method,
                ttl_seconds=1 if long_delay and method=='group.send' and profile=='anp.group.base.v1' else 300)}},actor['token'])
    try:
        start(0);start(1)
        owner=register(0,'old-owner');member=register(1,'old-member')
        policy={'message_security_profile':'transport-protected','bootstrap_security_profile':'transport-protected',
            'admission_mode':'admin-add','permissions':{'send':'member','add':'admin','remove':'admin',
            'update_profile':'admin','update_policy':'owner'},'max_members':'100'}
        group=group_rpc('group.create',owner,settings[0].service_did,{'group_profile':{'display_name':'Original outbox'},'group_policy':policy})['group_did']
        group_rpc('group.add',owner,group,{'member_did':member['did'],'role':'member'})
        until(lambda:rows(settings[1].db_path,"SELECT group_did FROM group_views WHERE group_did=? AND membership_status='active'",(group,)), 'original member projection')
        stop(1)
        sent=[group_rpc('group.send',owner,group,{'payload':{'text':'old queued '+str(i)}}) for i in range(2)]
        until(lambda:rows(settings[0].db_path,"SELECT delivery_id FROM group_delivery_outbox WHERE group_did=? AND status='retry'",(group,)), 'original offline retry')
        stop(0)
        assert 'wire_profile' not in {row['name'] for row in rows(settings[0].db_path,'PRAGMA table_info(hosted_groups)')}
        backlog=rows(settings[0].db_path,'SELECT delivery_id,method,envelope_json,status FROM group_delivery_outbox WHERE group_did=? ORDER BY delivery_id',(group,))
        immutable={item['delivery_id']:hashlib.sha256(item['envelope_json'].encode()).hexdigest() for item in backlog}
        create_app(settings[0])
        plan=inspect_group(settings[0],group)
        assert plan['unresolved_deliveries']
        prepare_group(settings[0],group,plan['plan_digest'],root/'migration-backup')
        if long_delay:
            expirations=[int(re.search(r'expires=(\d+)',json.loads(item['envelope_json'])['params']['auth']['origin_proof']['signatureInput']).group(1))
                for item in backlog if item['method']=='group.incoming']
            until(lambda:time.time()>max(expirations)+61,'real original proof expiry plus clock skew',seconds=75)
        start(1,upgraded=long_delay);start(0,upgraded=True)
        until(lambda:not rows(settings[0].db_path,"SELECT delivery_id FROM group_delivery_outbox WHERE group_did=? AND status!='delivered'",(group,)), 'real original v1 backlog drain')
        projected=rows(settings[1].db_path,'SELECT message_id,group_event_seq FROM group_message_views WHERE group_did=? ORDER BY group_event_seq',(group,))
        assert [row['message_id'] for row in projected]==[item['message_id'] for item in sent]
        for item in backlog:
            envelope=json.loads(item['envelope_json'])
            if envelope['method']!='group.incoming': continue
            payload=json.dumps(envelope,ensure_ascii=False,separators=(',',':')).encode()
            headers={'Content-Type':'application/json','x-anp-source-service-did':settings[0].service_did}
            url=settings[1].public_base_url+'/anp-im/rpc'
            signer=service_identity_from_settings(service_did=settings[0].service_did,
                endpoint=settings[0].public_base_url+'/anp-im/rpc',
                private_key_pem=settings[0].service_private_key_pem)
            headers.update(signer.sign_headers(url,'POST',headers,payload))
            assert client.post(url,headers=headers,content=payload).status_code==204
        assert len(rows(settings[1].db_path,'SELECT message_id FROM group_message_views WHERE group_did=?',(group,)))==2
        after=rows(settings[0].db_path,'SELECT delivery_id,envelope_json FROM group_delivery_outbox WHERE group_did=?',(group,))
        assert {item['delivery_id']:hashlib.sha256(item['envelope_json'].encode()).hexdigest() for item in after}==immutable
        stop(0);stop(1)
        create_app(settings[1]);start(1,upgraded=True)
        with runtime._DISCOVERY_CACHE_LOCK: runtime._DISCOVERY_CACHE.clear()
        migrated=apply_group(settings[0],group,plan['plan_digest'])
        assert migrated['migration_state']=='applied'
        start(0,upgraded=True)
        new_host=group_rpc('group.send',owner,group,{'payload':{'text':'host after cutover'}},profile='anp.group.base.v2')
        until(lambda:rows(settings[1].db_path,'SELECT message_id FROM group_message_views WHERE message_id=?',
            (new_host['message_id'],)), 'new v2 host message at original member Home')
        new_member=group_rpc('group.send',member,group,{'payload':{'text':'member after cutover'}},profile='anp.group.base.v2',index=1)
        until(lambda:rows(settings[1].db_path,'SELECT message_id FROM group_message_views WHERE message_id=?',
            (new_member['message_id'],)), 'new v2 member echo at original member Home')
        assert len(rows(settings[0].db_path,'SELECT message_id FROM hosted_group_messages WHERE group_did=?',(group,)))==4
        assert len(rows(settings[1].db_path,'SELECT message_id FROM group_message_views WHERE group_did=?',(group,)))==4
        retained=rows(settings[0].db_path,'SELECT delivery_id,envelope_json FROM group_delivery_outbox WHERE group_did=?',(group,))
        assert {item['delivery_id']:hashlib.sha256(item['envelope_json'].encode()).hexdigest()
            for item in retained if item['delivery_id'] in immutable}==immutable
        # Force a real get_info observation to precede two genuine signed
        # notifications. Delivery itself is never mocked or re-labelled.
        stop(0);start(0,upgraded=True,paused_delivery=True)
        delayed=group_rpc('group.send',owner,group,{'payload':{'text':'delayed after roster read'}},profile='anp.group.base.v2')
        latest=group_rpc('group.update_profile',owner,group,{'group_profile_patch':{'display_name':'Observed latest'}},profile='anp.group.base.v2')
        rpc(1,'group.list_members',{'group_did':group,'limit':100},member['token'])
        view=rows(settings[1].db_path,'SELECT * FROM group_views WHERE owner_did=? AND group_did=?',(member['did'],group))[0]
        assert view['observed_event_seq']==int(latest['group_event_seq'])
        assert not rows(settings[1].db_path,'SELECT message_id FROM group_message_views WHERE message_id=?',(delayed['message_id'],))
        manual_worker=create_app(settings[0])
        def drained():
            result=drain_group_outbox_once(manual_worker)
            assert result['dead']==0 and result['retried']==0
            return not rows(settings[0].db_path,"SELECT delivery_id FROM group_delivery_outbox WHERE group_did=? AND status!='delivered'",(group,))
        until(drained,'delayed notification delivery after roster observation')
        assert len(rows(settings[1].db_path,'SELECT message_id FROM group_message_views WHERE message_id=?',(delayed['message_id'],)))==1
        view=rows(settings[1].db_path,'SELECT * FROM group_views WHERE owner_did=? AND group_did=?',(member['did'],group))[0]
        assert view['group_event_seq']==int(latest['group_event_seq'])
        assert json.loads(view['profile_json'])['display_name']=='Observed latest'
        evidence={'baseline_commit':BASELINE,'baseline_archive_sha256':hashlib.sha256(archive).hexdigest(),
            'delivered_after_origin_expiry_and_skew':long_delay,
            'group_did':group,'original_payload_sha256':immutable,'old_message_ids':[item['message_id'] for item in sent],
            'verified':['original offline retry','new worker drains original signed v1 FIFO','duplicate notification is idempotent',
                        'original payload bytes unchanged','cutover after drain and peer upgrade',
                        'bidirectional v2 messages and original remote member echo',
                        'authenticated roster read before signed message/state notifications retains body and latest view']}
        (root/'outbox-upgrade-evidence.json').write_text(json.dumps(evidence,indent=2)+'\n')
        print(json.dumps({'ok':True,'verified':evidence['verified']}))
    finally:
        stop(0);stop(1);client.close()


if __name__=='__main__':
    os.umask(0o077)
    run(Path(sys.argv[1]).resolve())
