from pyfileguard.core import *
from pyfileguard.severity import classify
def test_created(): assert compare_snapshots({},{"a":"1"})[0].kind=="CREATED"
def test_modified(): assert compare_snapshots({"a":"1"},{"a":"2"})[0].kind=="MODIFIED"
def test_deleted(): assert compare_snapshots({"a":"1"},{})[0].kind=="DELETED"
def test_rename():
 e=compare_snapshots({"old":"x"},{"new":"x"})[0]; assert (e.kind,e.old_path,e.path)==("RENAMED","old","new")
def test_hmac(tmp_path):
 (tmp_path/"a").write_text("x"); b=sign_baseline(build_baseline([tmp_path]),"secret"); assert verify_baseline(b,"secret") and not verify_baseline(b,"bad")
def test_ignore(tmp_path):
 (tmp_path/"keep").write_text("x"); (tmp_path/"skip.log").write_text("x"); b=build_baseline([tmp_path],["*.log"]); v=next(iter(b["directories"].values())); assert "keep" in v and "skip.log" not in v
def test_severity(): assert classify("server.conf","MODIFIED")=="HIGH"
