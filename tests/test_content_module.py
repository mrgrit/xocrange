import hashlib
import io
import json
from pathlib import Path
import tarfile
import pytest

ROOT=Path(__file__).resolve().parents[1]
from xocrange import content_module as m


def package(tmp_path,version='a',extra=None):
    payload={'guides/test.json':json.dumps({'version':version}).encode()}
    manifest=json.dumps({'schema_version':'xoc.content-module/0.1.0','id':'community-academy','files':{k:m.sha(v) for k,v in payload.items()}}).encode()
    lock={'schema_version':'xoc.content-lock/0.1.0','repository':'https://github.com/mrgrit/xocrange_contents','commit':version*40,'manifest_sha256':m.sha(manifest)}
    archive=tmp_path/(version+'.tar.gz')
    with tarfile.open(archive,'w:gz') as t:
        for name,data in {'module.json':manifest,**payload}.items():
            info=tarfile.TarInfo('source/'+name);info.size=len(data);t.addfile(info,io.BytesIO(data))
        if extra:extra(t)
    return lock,archive


def use_lock(root,lock):
    (root/'content-lock.json').write_text(json.dumps(lock))


def test_verified_download_and_offline_reuse(tmp_path,monkeypatch):
    lock,archive=package(tmp_path);use_lock(tmp_path,lock)
    assert m.fetch(tmp_path,archive=archive)['status']=='installed'
    monkeypatch.setattr(m.urllib.request,'urlopen',lambda *a,**k:pytest.fail('Network access on verified cache'))
    assert m.fetch(tmp_path)['status']=='verified'
    assert m.fetch(tmp_path,verify_only=True)['commit']==lock['commit']


def test_content_update_and_local_edits_are_preserved(tmp_path):
    lock,archive=package(tmp_path);use_lock(tmp_path,lock);m.fetch(tmp_path,archive=archive)
    new,archive2=package(tmp_path,'b');use_lock(tmp_path,new);m.fetch(tmp_path,archive=archive2)
    p=tmp_path/'contents/guides/test.json';assert json.loads(p.read_text())['version']=='b'
    p.write_text('local author edit');use_lock(tmp_path,lock)
    with pytest.raises(ValueError,match='checksum'):m.fetch(tmp_path,archive=archive)
    assert p.read_text()=='local author edit'


def test_bad_update_keeps_installed_cache(tmp_path):
    lock,archive=package(tmp_path);use_lock(tmp_path,lock);m.fetch(tmp_path,archive=archive)
    new,_=package(tmp_path,'b');use_lock(tmp_path,new)
    with pytest.raises(ValueError,match='manifest'):m.fetch(tmp_path,archive=archive)
    assert m.verify(tmp_path/'contents',lock)==1


@pytest.mark.parametrize('kind',['traversal','symlink','duplicate','undeclared','oversized'])
def test_unsafe_archives_are_rejected_without_touching_destination(tmp_path,kind):
    def extra(t):
        name={'traversal':'source/../escape','duplicate':'source/guides/test.json','undeclared':'source/guides/extra.json'}.get(kind,'source/guides/bad.json')
        info=tarfile.TarInfo(name)
        if kind=='symlink':info.type=tarfile.SYMTYPE;info.linkname='/etc/passwd';t.addfile(info)
        elif kind=='oversized':info.size=m.MAX_FILE+1;t.addfile(info,io.BytesIO(b'x'*info.size))
        else:info.size=1;t.addfile(info,io.BytesIO(b'x'))
    lock,archive=package(tmp_path,extra=extra);use_lock(tmp_path,lock)
    with pytest.raises(ValueError):m.fetch(tmp_path,archive=archive)
    assert not (tmp_path/'contents').exists() and not (tmp_path/'escape').exists()


def test_unmanaged_directory_and_symlink_are_preserved(tmp_path):
    lock,archive=package(tmp_path);use_lock(tmp_path,lock)
    target=tmp_path/'contents';target.mkdir();p=target/'my-work.txt';p.write_text('author material')
    with pytest.raises(FileNotFoundError):m.fetch(tmp_path,archive=archive)
    assert p.read_text()=='author material'
    p.unlink();target.rmdir();target.symlink_to(tmp_path/'other',target_is_directory=True)
    with pytest.raises(ValueError,match='symlink'):m.fetch(tmp_path,archive=archive)


def test_metadata_pin_required_without_network(tmp_path):
    lock,_=package(tmp_path);use_lock(tmp_path,lock)
    with pytest.raises(ValueError,match='missing'):m.fetch(tmp_path,verify_only=True)
    lock['commit']='main';use_lock(tmp_path,lock)
    with pytest.raises(ValueError,match='identity'):m.read_lock(tmp_path/'content-lock.json')
