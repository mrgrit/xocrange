import base64
from pathlib import Path
import pytest
from xocrange.agents import enroll,list_agents
from xocrange.errors import XocError


class Manager:
    def __init__(self):self.created=False;self.calls=[]
    def authenticate(self):return 'test-token'
    def request(self,method,path,body=None,**kwargs):
        self.calls.append((method,path))
        key=base64.b64encode(('001 endpoint-one any '+'a'*64).encode()).decode()
        if method=='POST':
            self.created=True
            return 200,{'data':{'id':'001','key':key}}
        if path=='/agents/001/key':return 200,{'data':{'affected_items':[{'key':key}]}}
        return 200,{'data':{'affected_items':[{'id':'001','name':'endpoint-one','status':'active','key':key}] if self.created else []}}


def test_enrollment_preserves_identity_and_never_returns_key(tmp_path,monkeypatch):
    monkeypatch.setattr('xocrange.agents.os.geteuid',lambda:0)
    real_stat=Path.stat
    # Test owns a private directory; emulate root ownership in unprivileged CI.
    def root_stat(path,*args,**kwargs):
        import os
        fields=list(real_stat(path,*args,**kwargs));fields[4]=0
        return os.stat_result(fields)
    monkeypatch.setattr(Path,'stat',root_stat)
    directory=tmp_path/'private';directory.mkdir(mode=0o700);key=directory/'client.keys';manager=Manager()
    first=enroll(manager,'endpoint-one',key);second=enroll(manager,'endpoint-one',key)
    assert first==second and first['id']=='001' and 'key' not in first
    assert key.read_text()=='001 endpoint-one any '+'a'*64+'\n'
    assert key.stat().st_mode&0o777==0o600
    assert len([c for c in manager.calls if c[0]=='POST'])==1
    assert 'key' not in list_agents(manager)[0]
    key.write_text('different identity\n')
    with pytest.raises(XocError,match='Existing agent key'):enroll(manager,'endpoint-one',key)


def test_enrollment_rejects_untrusted_path_before_manager_request(tmp_path,monkeypatch):
    monkeypatch.setattr('xocrange.agents.os.geteuid',lambda:0)
    manager=Manager();link=tmp_path/'link';link.symlink_to(tmp_path/'missing')
    with pytest.raises(XocError):enroll(manager,'endpoint-one',link)
    with pytest.raises(XocError):enroll(manager,'../../root',tmp_path/'key')
    assert manager.calls==[]
