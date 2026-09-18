"""Opt-in source-to-source gate using RPC-created data from the frozen baseline.

This is owning protocol/storage evidence, not final CLI or public acceptance.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import zipfile

import httpx
import pytest
from anp.proof import verify_group_receipt_proof
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from awiki_open_server.app.main import create_app
from awiki_open_server.app.settings import Settings
from awiki_open_server.messaging.groups.migration import inspect_group, prepare_group, apply_group
from tests.conftest import rpc
from tests.test_group_v2 import group_call

BASELINE = '8c6a6fcc450693ef3e100b8e509d54fddc7f9656'
pytestmark = pytest.mark.skipif(os.environ.get('AWIKI_RUN_PROTOCOL_BASELINE') != '1',
    reason='set AWIKI_RUN_PROTOCOL_BASELINE=1 to run the immutable original-version data gate')


def snapshot(database, columns=None):
    tables = ['hosted_group_messages', 'hosted_group_events', 'hosted_group_members',
              'group_operations', 'direct_messages', 'thread_read_states']
    with sqlite3.connect(f'file:{database}?mode=ro', uri=True) as conn:
        if columns is None:
            columns = {table:[row[1] for row in conn.execute(f'PRAGMA table_info({table})')] for table in tables}
        digests = {}
        for table, names in columns.items():
            quoted = ','.join('"' + name + '"' for name in names)
            rows = sorted(conn.execute(f'SELECT {quoted} FROM {table}').fetchall(), key=repr)
            digests[table] = hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()
        return columns, digests


def extract_original_version(tmp_path):
    repo = Path(__file__).resolve().parents[1]
    original = tmp_path / 'original-package'
    original.mkdir()
    archive = subprocess.check_output(['git', 'archive', '--format=zip', BASELINE, 'src', 'tests'], cwd=repo)
    with zipfile.ZipFile(io.BytesIO(archive)) as package:
        for name in package.namelist():
            assert (original / name).resolve().is_relative_to(original.resolve())
        package.extractall(original)
    return original, archive


def seed_original_version(tmp_path, *, domain='testserver', base_url='http://testserver'):
    repo = Path(__file__).resolve().parents[1]
    original, archive = extract_original_version(tmp_path)
    root = tmp_path / 'fixture'
    env = {**os.environ, 'PYTHONPATH':str(original / 'src') + os.pathsep + str(original),
           'AWIKI_EXPECT_BASELINE_PACKAGE':str(original / 'src'),
           'AWIKI_BASELINE_DOMAIN':domain, 'AWIKI_BASELINE_BASE_URL':base_url}
    result = subprocess.run([sys.executable, str(repo / 'tests/fixtures/seed_protocol_baseline.py'), str(root)],
        cwd=original, env=env, capture_output=True, text=True, timeout=60)
    # The generator uses assertions with method names, never response bodies.
    assert result.returncode == 0, result.stderr[-2000:]
    return root, archive


@pytest.mark.asyncio
async def test_original_version_data_survives_schema_and_group_protocol_upgrade(tmp_path):
    root, archive = seed_original_version(tmp_path)
    seed = json.loads((root / 'seed.json').read_text())
    settings = Settings(data_dir=root / 'data', public_base_url='http://testserver',
        service_did='did:wba:testserver', did_domain='testserver',
        service_private_key_pem=(root / 'service-key.pem').read_text(), allow_unsigned_peer_dev=True)
    columns, before = snapshot(settings.db_path)
    with sqlite3.connect(f'file:{settings.db_path}?mode=ro', uri=True) as conn:
        document, key_path = conn.execute('SELECT document_json,key_reference FROM group_did_documents WHERE group_did=?', (seed['group_did'],)).fetchone()
    old_document = json.loads(document)
    key_digest = hashlib.sha256(Path(key_path).read_bytes()).hexdigest()
    app = create_app(settings)
    assert snapshot(settings.db_path, columns)[1] == before
    group = seed['group_did']
    inspected = inspect_group(settings, group)
    assert inspected['wire_profile'] == 'anp.group.base.v1'
    assert inspected['unresolved_deliveries'] == []
    prepare_group(settings, group, inspected['plan_digest'], tmp_path / 'migration-backup')
    migrated = apply_group(settings, group, inspected['plan_digest'])
    assert apply_group(settings, group, inspected['plan_digest']) == migrated
    assert snapshot(settings.db_path, columns)[1] == before
    assert hashlib.sha256(Path(key_path).read_bytes()).hexdigest() == key_digest
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://testserver') as client:
        owner, member = seed['identities']
        page = await rpc(client, '/im/rpc', 'group.list_messages', {'group_did':group, 'limit':2}, token=member['token'])
        assert 'result' in page
        assert len(page['result']['messages']) == 2
        assert page['result']['has_more'] is True
        following = await rpc(client, '/im/rpc', 'group.list_messages', {
            'group_did':group, 'since_seq':page['result']['next_since_seq'], 'limit':2}, token=member['token'])
        assert following['result']['has_more'] is False
        old_history = page['result']['messages'] + following['result']['messages']
        assert [item['message_id'] for item in old_history] == [item['message_id'] for item in seed['messages']]
        for index, (old, served) in enumerate(zip(seed['messages'], old_history)):
            assert served['body'] == {'text':f'old message {index}'}
            assert served['group_receipt'] == old['group_receipt']
            assert verify_group_receipt_proof(served['group_receipt'], old_document)
        ticket = await rpc(client, '/im/rpc', 'attachment.get_download_ticket', {'object_id':seed['object_id']}, token=owner['token'])
        assert 'result' in ticket
        download = await client.get('/objects/' + seed['object_id'], params={'ticket':ticket['result']['ticket']})
        assert download.status_code == 200
        assert hashlib.sha256(download.content).hexdigest() == seed['attachment_sha256']
        key = load_pem_private_key((root / 'baseline-member.pem').read_bytes(), password=None)
        sent = await group_call(client, (member['did'], member['token'], key, member['document']),
            'group.send', group, 'new-version-message', {'payload':{'text':'continued on original Group DID'}})
        assert sent['result']['group_did'] == group
        new_seq = int(sent['result']['group_event_seq'])
        assert new_seq == int(seed['messages'][-1]['group_event_seq']) + 1
        new_direct = await rpc(client, '/im/rpc', 'direct.send', {'to':member['did'], 'text':'new direct message'}, token=owner['token'])
        advanced = await rpc(client, '/im/rpc', 'read_state.mark_read', {'body':{'user_did':member['did'],
            'thread':{'kind':'direct', 'peer_did':owner['did']}, 'read_up_to_message_id':new_direct['result']['message_id']}}, token=member['token'])
        assert int(advanced['result']['read_watermark_server_seq']) > int(seed['read']['read_watermark_server_seq'])
    restarted = create_app(settings)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=restarted), base_url='http://testserver') as client:
        history = await rpc(client, '/im/rpc', 'group.list_messages', {'group_did':group, 'limit':100}, token=member['token'])
        assert len(history['result']['messages']) == 4
    evidence = {'baseline_commit':BASELINE, 'baseline_archive_sha256':hashlib.sha256(archive).hexdigest(),
        'old_table_digests':before, 'group_did':group, 'group_key_sha256':key_digest,
        'attachment_sha256':seed['attachment_sha256'], 'cli_acceptance':False}
    (tmp_path / 'upgrade-evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')


def run_original_cli_gate(tmp_path, *, legacy_listener=False):
    import shutil
    repo = Path(__file__).resolve().parents[1]
    binary = str(Path(os.environ['AWIKI_CLI_BIN']).resolve())
    assert Path(binary).is_file()
    for command in ['unshare', 'ip', 'mount']:
        assert shutil.which(command), f'{command} is required for the isolated HTTPS fixture'
    hosts = tmp_path / 'hosts'
    hosts.write_text(Path('/etc/hosts').read_text() + '\n127.0.0.1 legacy-open.test\n')
    env = {**os.environ, 'PYTHONPATH':str(repo / 'src') + os.pathsep + str(repo),
           'AWIKI_VERIFY_LEGACY_LISTENER':'1' if legacy_listener else '0'}
    result = subprocess.run(['unshare','-Urnm','sh','-c',
        'mount --bind "$1" /etc/hosts && "$2" link set lo up && shift 2 && exec "$@"',
        'sh',str(hosts),shutil.which('ip'),sys.executable,
        str(repo/'tests/fixtures/run_original_cli.py'),str(tmp_path),binary],
        cwd=repo,env=env,capture_output=True,text=True,timeout=180)
    assert result.returncode == 0, result.stderr[-3000:]
    assert json.loads(result.stdout)['ok'] is True


def test_original_signed_outbox_drains_before_protocol_cutover(tmp_path):
    import shutil
    repo = Path(__file__).resolve().parents[1]
    hosts = tmp_path / 'hosts'
    hosts.write_text(Path('/etc/hosts').read_text() + '\n127.0.0.1 outbox-host.test\n127.0.0.2 outbox-peer.test\n')
    env = {**os.environ, 'PYTHONPATH':str(repo/'src') + os.pathsep + str(repo)}
    result = subprocess.run(['unshare','-Urnm','sh','-c',
        'mount --bind "$1" /etc/hosts && "$2" link set lo up && shift 2 && exec "$@"',
        'sh',str(hosts),shutil.which('ip'),sys.executable,
        str(repo/'tests/fixtures/run_original_outbox.py'),str(tmp_path)],
        cwd=repo,env=env,capture_output=True,text=True,timeout=180)
    assert result.returncode == 0, result.stderr[-3000:]
    assert json.loads(result.stdout)['ok'] is True


def test_original_signed_outbox_survives_origin_expiry(tmp_path,monkeypatch):
    monkeypatch.setenv('AWIKI_TEST_LONG_DELAY','1')
    test_original_signed_outbox_drains_before_protocol_cutover(tmp_path)
    assert json.loads((tmp_path/'outbox-upgrade-evidence.json').read_text())['delivered_after_origin_expiry_and_skew'] is True


@pytest.mark.skipif(not os.environ.get('AWIKI_CLI_BIN'), reason='set AWIKI_CLI_BIN to the actual candidate CLI')
def test_original_members_continue_using_migrated_group_through_real_cli(tmp_path):
    run_original_cli_gate(tmp_path)


@pytest.mark.skipif(not os.environ.get('AWIKI_CLI_BIN'), reason='set AWIKI_CLI_BIN to the actual candidate CLI')
def test_original_root_only_listener_requires_vnext_binding(tmp_path):
    run_original_cli_gate(tmp_path, legacy_listener=True)


def test_complete_preupgrade_backup_restores_original_runtime(tmp_path):
    import shutil
    root, archive = seed_original_version(tmp_path)
    backup=tmp_path/'original-complete-backup'
    shutil.copytree(root,backup)
    # The seeding process has exited. Take a consistent SQLite backup rather
    # than relying on copied WAL timing; preserve every other server/key object.
    database=root/'data/awiki-open-server.sqlite3'
    with sqlite3.connect(f'file:{database}?mode=ro',uri=True) as source, sqlite3.connect(backup/'data/awiki-open-server.sqlite3') as target:
        source.backup(target)
    def logical_digest(path):
        with sqlite3.connect(f'file:{path}?mode=ro',uri=True) as conn:
            return hashlib.sha256('\n'.join(conn.iterdump()).encode()).hexdigest()
    original_digest=logical_digest(database)
    assert logical_digest(backup/'data/awiki-open-server.sqlite3')==original_digest
    settings=Settings(data_dir=root/'data',public_base_url='http://testserver',did_domain='testserver',
        service_did='did:wba:testserver',service_private_key_pem=(root/'service-key.pem').read_text())
    create_app(settings)
    seed=json.loads((root/'seed.json').read_text());group=seed['group_did']
    plan=inspect_group(settings,group)
    prepare_group(settings,group,plan['plan_digest'],tmp_path/'prepared-backup')
    apply_group(settings,group,plan['plan_digest'])
    assert inspect_group(settings,group)['wire_profile']=='anp.group.base.v2'
    # No server or user request has run since the backup; only this controlled
    # schema/protocol migration changed state. Preserve it before full restore.
    shutil.move(str(root/'data'),str(tmp_path/'upgraded-data-retained'))
    shutil.copytree(backup/'data',root/'data')
    assert logical_digest(database)==original_digest
    for file in (backup/'data').rglob('*'):
        if file.is_file() and file.suffix!='.sqlite3' and not file.name.endswith(('-wal','-shm')):
            assert file.read_bytes()==(root/'data'/file.relative_to(backup/'data')).read_bytes()
    assert (root/'service-key.pem').read_bytes()==(backup/'service-key.pem').read_bytes()
    repo=Path(__file__).resolve().parents[1];original=tmp_path/'original-package'
    result=subprocess.run([sys.executable,str(repo/'tests/fixtures/verify_original_restore.py'),str(root)],
        cwd=original,env={**os.environ,'PYTHONPATH':str(original/'src')+os.pathsep+str(original)},
        capture_output=True,text=True,timeout=60)
    assert result.returncode==0,result.stderr[-2000:]
    evidence=json.loads(result.stdout)
    evidence.update(original_database_logical_sha256=original_digest,baseline_commit=BASELINE,
        baseline_archive_sha256=hashlib.sha256(archive).hexdigest(),post_backup_business_writes=False)
    (tmp_path/'restore-evidence.json').write_text(json.dumps(evidence,indent=2)+'\n')
