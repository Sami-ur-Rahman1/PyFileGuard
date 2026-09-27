import pyfileguard.profiles as p
def test_profile(tmp_path,monkeypatch):
 monkeypatch.setattr(p,"PROFILE_DIR",tmp_path); p.save_profile("Web Server",["/var/www"],"/tmp/b",3,["*.log"]); assert p.load_profile("Web Server")["interval"]==3; assert p.delete_profile("Web Server")
