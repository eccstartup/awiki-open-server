"""Historical RPC data -> supported v1 credential import -> actual CLI gate."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import time

from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PublicFormat
from awiki_open_server.app.main import create_app
from awiki_open_server.app.settings import Settings
from awiki_open_server.messaging.groups.migration import inspect_group, prepare_group, apply_group
from scripts.awiki_open_cli import (generate_test_tls_material, initialize_rust_cli_workspace,
    rust_cli_json, start_open_server, stop_process, wait_health, assert_group_visible,
    assert_message_visible, assert_message_not_visible, rust_message_id, start_rust_cli_listener, _json_values_for_key)
from tests.test_original_version_upgrade import seed_original_version, BASELINE


def verify_legacy_listener_boundary(root, binary, workspaces, home):
    receiver=workspaces[1]
    rust_cli_json(binary,receiver,home,'runtime','listener','config','set','--enabled=false','--auto-install=false','--auto-start=false')
    rust_cli_json(binary,receiver,home,'runtime','mode','set','websocket')
    rust_cli_json(binary,receiver,home,'runtime','host-notify','config','set','--sink','file')
    rust_cli_json(binary,receiver,home,'runtime','host-notify','enable')
    rust_cli_json(binary,receiver,home,'runtime','listener','config','set','--enabled=true','--auto-install=false','--auto-start=false')
    listener=start_rust_cli_listener(binary,receiver,home)
    observation={'connected':False,'binding_refused':False,'reason_flags':[]}
    try:
        deadline=time.monotonic()+15
        while time.monotonic()<deadline and listener.poll() is None:
            status=rust_cli_json(binary,receiver,home,'runtime','listener','status')
            raw=json.dumps(status)
            observation['connected']=True in _json_values_for_key(status,'connected')
            observation['reason_flags']=[reason for reason in ['active-sync-account-binding','permission denied','identity provider','unsupported','VNext device identity','onboarding migrate-legacy'] if reason in raw]
            errors=_json_values_for_key(status,'last_error')
            if errors and all('reliable v2 sync requires a VNext device identity' in str(error) for error in errors):
                assert True not in _json_values_for_key(status,'connected')
                assert True not in _json_values_for_key(status,'v2_bootstrap_completed')
                assert True not in _json_values_for_key(status,'v2_subprotocol_negotiated')
                assert True not in _json_values_for_key(status,'legacy_sync_used')
                observation['binding_refused']=True
                break
            time.sleep(.2)
        observation['exit_code']=listener.poll()
        assert observation['binding_refused'], 'Root-only listener must expose the existing vNext binding requirement'
    finally:
        stop_process(listener)
        (root/'legacy-listener-evidence.json').write_text(json.dumps(observation,indent=2)+'\n')
        rust_cli_json(binary,receiver,home,'runtime','listener','config','set','--enabled=false','--auto-install=false','--auto-start=false')
        rust_cli_json(binary,receiver,home,'runtime','mode','set','http')


def run(root: Path, binary: str):
    domain = 'legacy-open.test'
    base = 'https://' + domain
    ca, cert, tls_key = generate_test_tls_material(root, [domain])
    os.environ['SSL_CERT_FILE'] = str(ca)
    os.environ['NO_PROXY'] = os.environ['no_proxy'] = '*'
    for key in ['HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy']:
        os.environ.pop(key, None)
    fixture, archive = seed_original_version(root, domain=domain, base_url=base)
    seed = json.loads((fixture / 'seed.json').read_text())
    service_key = (fixture / 'service-key.pem').read_text()
    settings = Settings(data_dir=fixture / 'data', public_base_url=base, did_domain=domain,
        service_did='did:wba:' + domain, service_private_key_pem=service_key)
    create_app(settings)
    group = seed['group_did']
    inspected = inspect_group(settings, group)
    prepare_group(settings, group, inspected['plan_digest'], root / 'migration-backup')
    apply_group(settings, group, inspected['plan_digest'])
    home = root / 'client-home'
    # This is the CLI's documented legacy credential layout, not an Agent host.
    credentials = home / '.openclaw/credentials/awiki-agent-id-message'
    credentials.mkdir(parents=True, mode=0o700)
    workspaces = []
    for identity in seed['identities']:
        handle = identity['handle']
        pem = (fixture / (handle + '.pem')).read_text()
        key = load_pem_private_key(pem.encode(), password=None)
        payload = {'did':identity['did'], 'unique_id':handle, 'name':handle,
            'handle':handle, 'user_id':identity['user_id'], 'jwt_token':identity['token'],
            'did_document':identity['document'], 'private_key_pem':pem,
            'public_key_pem':key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()}
        (credentials / (handle + '.json')).write_text(json.dumps(payload))
        workspace = root / ('cli-' + handle)
        initialize_rust_cli_workspace(binary, workspace, home, base_url=base, did_domain=domain, ca_bundle=ca)
        config = workspace / 'tenants/local/config.yaml'
        text, changed = re.subn(r'(secret_storage:\n  mode:) [^\n]+', r'\1 file_compat', config.read_text())
        assert changed == 1
        config.write_text(text)
        rust_cli_json(binary, workspace, home, '--migration', 'id', 'import-v1', '--name', handle, '--credentials-dir', str(credentials))
        workspaces.append(workspace)
    def start():
        process = start_open_server(data_dir=settings.data_dir, port=443, domain=domain,
            private_key_pem=service_key, resolver_map={domain:base}, public_base_url=base,
            ssl_certfile=cert, ssl_keyfile=tls_key)
        try: wait_health(base, process)
        except BaseException:
            stop_process(process)
            raise
        return process
    process = start()
    try:
        owner_did, member_did = [item['did'] for item in seed['identities']]
        old_direct = rust_cli_json(binary,workspaces[1],home,'msg','history','--with',owner_did,'--limit','20')
        assert_message_visible(old_direct,message_id=seed['direct']['message_id'],text='old direct message')
        downloaded = root / 'original-attachment-download.bin'
        rust_cli_json(binary,workspaces[1],home,'msg','attachment','download','--with',owner_did,
            '--message-id',seed['attachment_message_id'],'--output',str(downloaded))
        assert hashlib.sha256(downloaded.read_bytes()).hexdigest() == seed['attachment_sha256']
        rust_cli_json(binary,workspaces[1],home,'msg','mark-read',seed['attachment_message_id'])
        with sqlite3.connect(f'file:{settings.db_path}?mode=ro',uri=True) as connection:
            row = connection.execute('SELECT read_up_to_seq FROM thread_read_states WHERE owner_did=? AND thread_id=?',
                (member_did,'direct:'+owner_did)).fetchone()
            assert row and int(row[0]) > int(seed['read']['read_watermark_server_seq'])
        unread = rust_cli_json(binary,workspaces[1],home,'msg','inbox','--scope','direct','--unread','--limit','20')
        assert_message_not_visible(unread,message_id=seed['attachment_message_id'])
        for workspace in workspaces:
            assert_group_visible(rust_cli_json(binary, workspace, home, 'group', 'list', '--limit','50'), group_did=group)
            first = rust_cli_json(binary,workspace,home,'group','messages','--group',group,'--limit','2')
            assert first['data']['has_more'] is True
            following = rust_cli_json(binary,workspace,home,'group','messages','--group',group,'--limit','2',
                '--cursor',str(first['data']['next_since_seq']))
            assert following['data']['has_more'] is False
            history = {'data':{'messages':first['data']['messages'] + following['data']['messages']}}
            for index, message in enumerate(seed['messages']):
                assert_message_visible(history, message_id=message['message_id'], text=f'old message {index}')
        new_ids=[]
        for index, workspace in enumerate(workspaces):
            sent=rust_cli_json(binary, workspace, home, 'msg','send','--group',group,'--text',f'upgraded member {index}')
            new_ids.append(rust_message_id(sent))
        for workspace in workspaces:
            history=rust_cli_json(binary,workspace,home,'group','messages','--group',group,'--limit','20')
            for index, message_id in enumerate(new_ids):
                assert_message_visible(history,message_id=message_id,text=f'upgraded member {index}')
        if os.environ.get('AWIKI_VERIFY_LEGACY_LISTENER')=='1':
            verify_legacy_listener_boundary(root,binary,workspaces,home)
    finally: stop_process(process)
    process=start()
    try:
        second_download = root / 'original-attachment-after-restart.bin'
        rust_cli_json(binary,workspaces[1],home,'msg','attachment','download','--with',owner_did,
            '--message-id',seed['attachment_message_id'],'--output',str(second_download))
        assert hashlib.sha256(second_download.read_bytes()).hexdigest() == seed['attachment_sha256']
        for workspace in workspaces:
            history=rust_cli_json(binary,workspace,home,'group','messages','--group',group,'--limit','20')
            for index, message_id in enumerate(new_ids):
                assert_message_visible(history,message_id=message_id,text=f'upgraded member {index}')
    finally: stop_process(process)
    evidence={'baseline_commit':BASELINE,'baseline_archive_sha256':hashlib.sha256(archive).hexdigest(),
        'cli_sha256':hashlib.sha256(Path(binary).read_bytes()).hexdigest(),'group_did':group,
        'original_member_dids':[item['did'] for item in seed['identities']],
        'verified':['supported id import-v1','same original members and Group DID','paginated original group history',
                    'original Direct history','original attachment downloaded by recipient',
                    'original read watermark advanced','bidirectional new messages','restart persistence']}
    (root/'cli-upgrade-evidence.json').write_text(json.dumps(evidence,indent=2)+'\n')
    print(json.dumps({'ok':True,'verified':evidence['verified']}))


if __name__=='__main__':
    os.umask(0o077)
    run(Path(sys.argv[1]).resolve(), str(Path(sys.argv[2]).resolve()))
