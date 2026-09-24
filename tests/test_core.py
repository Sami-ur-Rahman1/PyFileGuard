from pyfileguard.core import diff,get_events,log_changes,snapshot

def test_modified(tmp_path):
 f=tmp_path/"a.txt"; f.write_text("one"); old=snapshot(tmp_path); f.write_text("two"); assert diff(old,snapshot(tmp_path))["modified"]==["a.txt"]

def test_created_deleted(tmp_path):
 a=tmp_path/"a.txt"; a.write_text("a"); old=snapshot(tmp_path); a.unlink(); (tmp_path/"b.txt").write_text("b"); c=diff(old,snapshot(tmp_path)); assert c["deleted"]==["a.txt"] and c["created"]==["b.txt"]

def test_rename(tmp_path):
 a=tmp_path/"a.txt"; a.write_text("same"); old=snapshot(tmp_path); a.rename(tmp_path/"b.txt"); c=diff(old,snapshot(tmp_path)); assert c["renamed"][0]["from"]=="a.txt" and c["renamed"][0]["to"]=="b.txt"

def test_ignores(tmp_path):
 (tmp_path/"keep.txt").write_text("x"); (tmp_path/"temp.txt~").write_text("x"); s=snapshot(tmp_path); assert "keep.txt" in s["files"] and "temp.txt~" not in s["files"]

def test_history(tmp_path):
 db=tmp_path/"e.db"; ids=log_changes(db,{"created":["x"],"deleted":[],"modified":[],"renamed":[]},tmp_path); assert ids==[1]; assert get_events(db)[0]["event_type"]=="CREATED"
