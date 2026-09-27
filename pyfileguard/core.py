from __future__ import annotations
import fnmatch, hashlib, hmac, json, os, time
from dataclasses import dataclass
from pathlib import Path

DEFAULT_IGNORES=[".git",".venv","venv","__pycache__",".pytest_cache","*.pyc","*.pyo","*.tmp","*.swp","*~",".DS_Store"]

@dataclass(frozen=True)
class Event:
    kind:str
    path:str
    old_path:str|None=None
    severity:str="MEDIUM"

def sha256_file(path):
    h=hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""): h.update(chunk)
    return h.hexdigest()

def ignored(rel,patterns):
    rel=rel.replace(os.sep,"/")
    return any(fnmatch.fnmatch(rel,p) or any(fnmatch.fnmatch(part,p) for part in rel.split("/")) for p in patterns)

def scan_directory(directory,ignores=None):
    root=Path(directory).expanduser().resolve()
    if not root.is_dir(): raise ValueError(f"Not a directory: {root}")
    pats=DEFAULT_IGNORES+list(ignores or [])
    out={}
    for p in root.rglob("*"):
        if p.is_file():
            rel=p.relative_to(root).as_posix()
            if not ignored(rel,pats):
                try: out[rel]=sha256_file(p)
                except OSError: pass
    return out

def build_baseline(directories,ignores=None):
    roots=[str(Path(d).expanduser().resolve()) for d in directories]
    return {"format":2,"created_at":int(time.time()),"directories":{r:scan_directory(r,ignores) for r in roots},"ignores":list(ignores or [])}

def payload(b):
    x=dict(b); x.pop("integrity",None)
    return json.dumps(x,sort_keys=True,separators=(",",":")).encode()

def sign_baseline(b,key):
    x=dict(b); x["integrity"]={"algorithm":"HMAC-SHA256","digest":hmac.new(key.encode(),payload(b),hashlib.sha256).hexdigest()}; return x

def verify_baseline(b,key):
    expected=(b.get("integrity") or {}).get("digest")
    return bool(expected) and hmac.compare_digest(expected,hmac.new(key.encode(),payload(b),hashlib.sha256).hexdigest())

def save_baseline(b,path):
    p=Path(path).expanduser(); p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(b,indent=2),encoding="utf-8")

def load_baseline(path): return json.loads(Path(path).expanduser().read_text(encoding="utf-8"))

def compare_snapshots(old,new):
    deleted={p:h for p,h in old.items() if p not in new}; created={p:h for p,h in new.items() if p not in old}
    events=[]; used=set()
    for op,oh in sorted(deleted.items()):
        match=next((p for p,h in sorted(created.items()) if p not in used and h==oh),None)
        if match: events.append(Event("RENAMED",match,op)); used.add(match)
        else: events.append(Event("DELETED",op))
    events += [Event("CREATED",p) for p in sorted(created) if p not in used]
    events += [Event("MODIFIED",p) for p in sorted(old.keys()&new.keys()) if old[p]!=new[p]]
    return events

def compare_baseline(b,ignores=None):
    merged=list(b.get("ignores",[]))+list(ignores or []); out=[]
    for root,old in b.get("directories",{}).items():
        out += [(root,e) for e in compare_snapshots(old,scan_directory(root,merged))]
    return out
