import io
import json
import os
from pathlib import Path
import tarfile

import pytest
from xocrange import operations as ops
from xocrange.errors import XocError
from xocrange.lifecycle import selection_arguments
from xocrange.image_lock import checked, override
from xocrange.documents import canonical


def archive(path, entries):
    with tarfile.open(path, 'w:gz') as out:
        root = tarfile.TarInfo('data'); root.type = tarfile.DIRTYPE; root.mode = 0o755; out.addfile(root)
        for name, kind, content in entries:
            item = tarfile.TarInfo(name); item.uid = os.getuid(); item.gid = os.getgid()
            if kind == 'symlink': item.type = tarfile.SYMTYPE; item.linkname = content
            elif kind == 'hardlink': item.type = tarfile.LNKTYPE; item.linkname = content
            elif kind == 'device': item.type = tarfile.CHRTYPE
            else: item.size = len(content); item.mode = 0o600
            out.addfile(item, io.BytesIO(content) if kind == 'file' else None)
    path.chmod(0o600)


@pytest.mark.parametrize('entries', [
    [('../escape','file',b'x')], [('/etc/escape','file',b'x')],
    [('data/a','file',b'x'),('data/a','file',b'y')],
    [('data/link','symlink','/etc'),('data/link/config','file',b'x')],
    [('data/link','hardlink','../../etc/passwd')], [('data/device','device','')],
])
def test_restore_rejects_archive_traversal_duplicates_and_devices(tmp_path, entries):
    path = tmp_path/'data.tar.gz'; archive(path, entries)
    with pytest.raises(XocError, match='archive|Archive|hard link'):
        ops.unpack(path, tmp_path/'output')
    assert not (tmp_path/'escape').exists()


def test_regular_files_and_container_relative_links_restore_without_following(tmp_path):
    path = tmp_path/'data.tar.gz'
    archive(path, [('data/file','file',b'evidence'),('data/copy','hardlink','data/file'),('data/ar.conf','symlink','../../var/ar.conf')])
    # Tar root is owned by the test user, too.
    with tarfile.open(path, 'r:gz') as a:
        assert len(ops.members(a)) == 4
    original = ops.os.chown
    try:
        ops.os.chown = lambda *args, **kwargs: None
        restored = ops.unpack(path, tmp_path/'output')
    finally:
        ops.os.chown = original
    assert (restored/'file').read_bytes() == (restored/'copy').read_bytes() == b'evidence'
    assert (restored/'ar.conf').is_symlink()
    assert os.readlink(restored/'ar.conf') == '../../var/ar.conf'


def test_backup_verification_precedes_any_restore_mutation(tmp_path, monkeypatch):
    directory = tmp_path/'backup'; directory.mkdir(mode=0o700)
    state = {'release':'/opt/xocrange/releases/'+'a'*64, 'plan':'install-'+'b'*64}
    files = {}
    for name in ('source.tar.gz','venv.tar.gz','state-last-install.json.tar.gz'):
        archive(directory/name, [('data/file','file',b'original')])
        files[name] = {'sha256':ops.sha256(directory/name),'bytes':(directory/name).stat().st_size,'expanded_bytes':8}
    ops.save(directory/'manifest.json', {'schema_version':'xoc.backup/0.1.0','status':'complete','installation':state,'files':files,'portable':False,'units':[]})
    assert ops.verify_backup(directory)['status'] == 'complete'
    (directory/'source.tar.gz').write_bytes(b'changed')
    monkeypatch.setattr(ops, 'installed', lambda: pytest.fail('must not inspect or mutate the deployment'))
    monkeypatch.setattr(ops, 'stop', lambda: pytest.fail('must not stop services'))
    with pytest.raises(XocError) as exc:
        ops.restore(directory)
    assert exc.value.code == 'backup_checksum'


def test_private_backup_paths_and_symlinks(tmp_path):
    public = tmp_path/'public'; public.mkdir(mode=0o755)
    with pytest.raises(XocError): ops.private(public)
    link = tmp_path/'redirect'; link.symlink_to(public)
    with pytest.raises(XocError): ops.private(link/'new', exists=False)


def test_failed_backup_restarts_previously_active_services(tmp_path, monkeypatch):
    output = tmp_path/'backup'
    source = tmp_path/'source'; source.mkdir()
    monkeypatch.setattr(ops, 'installed', lambda: {})
    monkeypatch.setattr(ops, 'volume_paths', lambda: {})
    monkeypatch.setattr(ops, 'paths', lambda *a: {'source':source})
    monkeypatch.setattr(ops, 'image_inventory', lambda _: {})
    monkeypatch.setattr(ops, 'active_units', lambda: ['core'])
    calls = []
    monkeypatch.setattr(ops, 'stop', lambda: calls.append('stop'))
    monkeypatch.setattr(ops, 'resume', lambda units: calls.append(tuple(units)))
    def fail(*args): raise OSError('injected disk failure')
    monkeypatch.setattr(ops, 'pack', fail)
    with pytest.raises(OSError): ops.create(output, portable=False)
    assert calls == ['stop', ('core',)]
    assert not (output/'manifest.json').exists()
    assert (output/'journal.json').is_file()


def test_selection_removal_is_explicit_and_reinstall_preserves_other_options():
    args = selection_arguments({'platform','security-path','management','fixture-security-probe','noc','fixture-one'})
    pairs = set(zip(args[::2], args[1::2]))
    assert ('--include','noc') in pairs and ('--include','fixture-one') in pairs
    assert ('--without','siem') in pairs and ('--without','console-fw') in pairs
    assert ('--without','noc') not in pairs


def test_image_lock_rejects_tampered_override_and_wrong_service_set(tmp_path):
    import hashlib, yaml
    (tmp_path/'plan.lock.json').write_text(json.dumps({'plan_id':'p'}))
    (tmp_path/'compose.yaml').write_text('services:\n  platform: {}\n')
    value = {'schema_version':'xoc.images/0.1.0','plan_id':'p','services':{'platform':{'id':'sha256:'+'a'*64,'reference':'example:tag','repo_digests':[]}}}
    value['sha256'] = hashlib.sha256(canonical(value)).hexdigest()
    (tmp_path/'images.lock.json').write_text(json.dumps(value))
    (tmp_path/'compose.images.yaml').write_text(yaml.safe_dump(override(value)))
    assert checked(tmp_path) == tmp_path/'compose.images.yaml'
    (tmp_path/'compose.images.yaml').write_text('services:\n  platform:\n    image: attacker:latest\n')
    with pytest.raises(XocError) as exc: checked(tmp_path)
    assert exc.value.code == 'image_lock_invalid'


def test_retained_images_have_content_specific_tags_before_rebuild(monkeypatch):
    from types import SimpleNamespace
    from xocrange import image_lock
    calls = []
    monkeypatch.setattr(image_lock.subprocess, 'run', lambda args, **kwargs: calls.append(args) or SimpleNamespace(returncode=0))
    image_lock.retain({'platform':{'id':'sha256:'+'a'*64}})
    image_lock.retain({'platform':{'id':'sha256:'+'b'*64}})
    assert calls[0][-1] != calls[1][-1]
    assert calls[0][-2:] == ['sha256:'+'a'*64, 'xocrange-retained/platform:'+'a'*64]


@pytest.mark.parametrize('same_host', [True, False])
def test_restore_rebinds_file_cursors_without_replaying_and_resumes_journal(tmp_path, monkeypatch, same_host):
    import sqlite3
    monkeypatch.setattr(ops, 'STATE', tmp_path)
    (tmp_path/'siem').mkdir()
    volume = tmp_path/'log'; volume.mkdir()
    log = volume/'eve.json'; log.write_text('old log\n')
    old = 'suricata:'+ops.PROJECT+'_ips-logs:9:123'
    with sqlite3.connect(tmp_path/'siem/events.sqlite3') as db:
        db.execute('CREATE TABLE cursors (name TEXT PRIMARY KEY, value TEXT)')
        db.executemany('INSERT INTO cursors VALUES (?,?)', [(old,json.dumps({'offset':8,'buffer':'','file':'/old/eve.json'})), ('sysmon-journal',json.dumps({'cursor':'old-host-cursor','source_time':12345}))])
    data = {'machine_id':Path('/etc/machine-id').read_text().strip() if same_host else 'different-host',
            'cursor_bindings':[{'cursor':old,'volume':'ips-logs','relative':'eve.json'}]}
    ops.rebase_cursors(data, {'ips-logs':volume})
    with sqlite3.connect(tmp_path/'siem/events.sqlite3') as db:
        rows = {k:json.loads(v) for k,v in db.execute('SELECT name,value FROM cursors')}
    new = old.rsplit(':',2)[0]+f':{log.stat().st_dev}:{log.stat().st_ino}'
    assert old not in rows and rows[new]['offset'] == 8 and rows[new]['file'] == str(log)
    assert 'sysmon-journal' not in rows
    assert rows['sysmon-journal-resume']['since'] == (12344 if same_host else 0)


def test_compressed_receipt_cursors_keep_completion_after_restoring_new_inodes(tmp_path,monkeypatch):
    import gzip,sqlite3
    monkeypatch.setattr(ops,'STATE',tmp_path)
    (tmp_path/'siem').mkdir();volume=tmp_path/'logs';volume.mkdir()
    file=volume/'old.json.gz';file.write_bytes(gzip.compress(b'processed\n'))
    old='wazuh-archives:'+ops.PROJECT+'_siem-logs:1:2'
    with sqlite3.connect(tmp_path/'siem/events.sqlite3') as db:
        db.execute('CREATE TABLE cursors (name TEXT PRIMARY KEY,value TEXT)')
        db.execute('INSERT INTO cursors VALUES (?,?)',(old,json.dumps({'file':str(file).removesuffix('.gz'),'offset':10,'buffer':'','complete':True,'compressed_signature':[3,4,5]})))
    bindings=ops.cursor_bindings({'siem-logs':volume})
    assert bindings==[{'cursor':old,'volume':'siem-logs','relative':'old.json.gz'}]
    ops.rebase_cursors({'cursor_bindings':bindings},{'siem-logs':volume})
    with sqlite3.connect(tmp_path/'siem/events.sqlite3') as db:rows={n:json.loads(v) for n,v in db.execute('SELECT * FROM cursors')}
    assert old not in rows
    from xocrange.collector import read_snapshots
    assert read_snapshots(str(volume/'missing.json'),'wazuh-archives:'+ops.PROJECT+'_siem-logs',rows,history=[file])==[]


def test_sysmon_is_not_duplicated_into_syslog():
    # The collector reads Sysmon from journald; rsyslog must not also copy it
    # into /var/log/syslog, and the rule must follow backup/restore.
    from xocrange import operations
    script = (Path(__file__).resolve().parents[1]/'scripts/install-operations.sh').read_text()
    rule = operations.HOST_PATHS['rsyslog-sysmon']
    assert str(rule) in script
    assert ':programname, isequal, "sysmon" stop' in script
    assert rule.name < '50-default.conf'


def _restorable(tmp_path, monkeypatch):
    state_dir = tmp_path/'state'; state_dir.mkdir(mode=0o700); (state_dir/'backups').mkdir(mode=0o700)
    monkeypatch.setattr(ops, 'STATE', state_dir)
    directory = tmp_path/'backup'; directory.mkdir(mode=0o700)
    state = {'release':'/opt/xocrange/releases/'+'a'*64, 'plan':'install-'+'b'*64, 'data_directory':'/data'}
    files = {}
    for name in ('source.tar.gz','venv.tar.gz','state-last-install.json.tar.gz'):
        archive(directory/name, [('data/file','file',b'original')])
        files[name] = {'sha256':ops.sha256(directory/name),'bytes':(directory/name).stat().st_size,'expanded_bytes':8}
    image = {'id':'sha256:'+'c'*64, 'reference':'example@sha256:'+'c'*64}
    ops.save(directory/'manifest.json', {'schema_version':'xoc.backup/0.1.0','status':'complete','installation':state,
                                         'files':files,'portable':False,'units':[],'images':{'web':image}})
    monkeypatch.setattr(ops, 'installed', lambda: state)
    monkeypatch.setattr(ops, 'create', lambda *a, **k: None)
    monkeypatch.setattr(ops, 'unpack', lambda source, target: target)
    monkeypatch.setattr(ops, 'stop', lambda: pytest.fail('must not stop services'))
    def command(args, **kwargs):
        raise XocError('operation_command', 'image missing')
    monkeypatch.setattr(ops, 'command', command)
    return directory, state_dir/'restore-operation.json'


def test_restore_failing_before_mutation_is_not_recoverable(tmp_path, monkeypatch):
    directory, journal = _restorable(tmp_path, monkeypatch)
    with pytest.raises(XocError):
        ops.restore(directory)
    value = json.loads(journal.read_text())
    # Nothing changed, so `xoc recover` must not roll back to this checkpoint later.
    assert value['status'] == 'aborted'
    assert ops.recover() == {'status':'no-recovery-needed'}


def test_failed_recovery_run_keeps_its_recovery_point(tmp_path, monkeypatch):
    directory, journal = _restorable(tmp_path, monkeypatch)
    with pytest.raises(XocError):
        ops.restore(directory, checkpoint=False)
    value = json.loads(journal.read_text())
    assert value['status'] == 'failed' and value['recovery'] == str(directory)


def test_successful_install_keeps_only_its_checkpoint(tmp_path):
    state = tmp_path/'state'; backups = state/'backups'; backups.mkdir(parents=True)
    names = ['before-install-20261108T150908-1', 'before-install-20261111T155720-2',
             'before-install-20261111T162201-3', 'manual-001', 'before-restore-20261108T070000000000Z']
    for name in names:
        (backups/name).mkdir(); (backups/name/'manifest.json').write_text('{}')
    # An unfinished restore still needs its recovery point.
    (state/'restore-operation.json').write_text(json.dumps({'status':'failed', 'recovery':str(backups/names[1])}))
    result = ops.prune_checkpoints(backups/names[2], backups)
    assert result['removed'] == [names[0]]
    assert sorted(p.name for p in backups.iterdir()) == sorted(names[1:])
    with pytest.raises(XocError):
        ops.prune_checkpoints(backups/'manual-001', backups)


def test_volume_paths_inspects_all_volumes_in_one_call(monkeypatch, tmp_path):
    import types
    calls = []
    names = [ops.PROJECT + '_' + n for n in ('siem-logs', 'web-logs', 'platform-socket', 'platform-observation')]
    def item(name, **extra):
        short = name[len(ops.PROJECT)+1:]
        (tmp_path/short).mkdir(exist_ok=True)
        return dict({'Name': name, 'Driver': 'local', 'Options': None, 'Mountpoint': str(tmp_path/short),
                     'Labels': {'com.docker.compose.project': ops.PROJECT, 'com.docker.compose.volume': short}}, **extra)
    inspected = {'value': [item(names[0]), item(names[1])]}
    def command(args, **kw):
        calls.append(args)
        out = '\n'.join(names) if args[4] == 'ls' else json.dumps(inspected['value'])
        return types.SimpleNamespace(stdout=out, returncode=0)
    monkeypatch.setattr(ops, 'command', command)
    assert ops.volume_paths() == {'siem-logs': tmp_path/'siem-logs', 'web-logs': tmp_path/'web-logs'}
    assert [c[4] for c in calls] == ['ls', 'inspect'] and calls[1][5:] == names[:2]
    inspected['value'] = [item(names[0])]
    with pytest.raises(XocError):
        ops.volume_paths()
    inspected['value'] = [item(names[0]), item(names[1], Driver='nfs')]
    with pytest.raises(XocError):
        ops.volume_paths()

