import json
from pathlib import Path
PROFILE_DIR=Path.home()/".pyfileguard"/"profiles"
def safe(name):
    x="".join(c for c in name if c.isalnum() or c in "-_ ").strip()
    if not x: raise ValueError("Profile name cannot be empty.")
    return x.replace(" ","_")
def save_profile(name,directories,baseline,interval=5,ignores=None):
    PROFILE_DIR.mkdir(parents=True,exist_ok=True); p=PROFILE_DIR/f"{safe(name)}.json"
    p.write_text(json.dumps({"name":name,"directories":list(directories),"baseline":str(baseline),"interval":max(1,int(interval)),"ignores":list(ignores or [])},indent=2),encoding="utf-8"); return p
def list_profiles(): PROFILE_DIR.mkdir(parents=True,exist_ok=True); return sorted(PROFILE_DIR.glob("*.json"))
def load_profile(name):
    p=Path(name).expanduser()
    if not p.exists(): p=PROFILE_DIR/f"{safe(str(name))}.json"
    return json.loads(p.read_text(encoding="utf-8"))
def delete_profile(name):
    p=PROFILE_DIR/f"{safe(name)}.json"
    if p.exists(): p.unlink(); return True
    return False
