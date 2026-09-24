from __future__ import annotations
import fnmatch, hashlib, json, os, sqlite3
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_IGNORES = [".git", ".git/*", ".venv", ".venv/*", "venv", "venv/*",
"__pycache__", "*/__pycache__", "*/__pycache__/*", ".pytest_cache", ".pytest_cache/*",
"*.pyc", "*.pyo", "*.tmp", "*.swp", "*~"]

def utc_now():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")

def sha256(path, chunk_size=1024*1024):
    h=hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda:f.read(chunk_size), b""): h.update(chunk)
    return h.hexdigest()

def _ignored(rel, patterns):
    rel=rel.replace(os.sep,"/"); parts=rel.split("/")
    for pat in patterns:
        p=pat.replace(os.sep,"/")
        if fnmatch.fnmatch(rel,p) or fnmatch.fnmatch(Path(rel).name,p): return True
        if "/" not in p and p in parts: return True
    return False

def snapshot(root, ignore_patterns=None):
    root=Path(root).expanduser().resolve()
    if not root.exists(): raise FileNotFoundError(f"Directory not found: {root}")
    if not root.is_dir(): raise NotADirectoryError(f"Not a directory: {root}")
    patterns=list(DEFAULT_IGNORES if ignore_patterns is None else ignore_patterns)
    out={"root":str(root),"created_at":utc_now(),"files":{},"errors":[]}
    for p in sorted(root.rglob("*")):
        try:
            if not p.is_file(): continue
            rel=p.relative_to(root).as_posix()
            if _ignored(rel,patterns): continue
            st=p.stat()
            out["files"][rel]={"sha256":sha256(p),"size":st.st_size,"mtime_ns":st.st_mtime_ns}
        except (OSError,PermissionError) as e:
            out["errors"].append({"path":str(p),"error":str(e)})
    return out

def diff(old,new):
    a,b=old.get("files",{}),new.get("files",{})
    ap,bp=set(a),set(b)
    created=sorted(bp-ap); deleted=sorted(ap-bp)
    modified=sorted(p for p in ap&bp if a[p].get("sha256")!=b[p].get("sha256"))
    byhash={}
    for p in created: byhash.setdefault(b[p]["sha256"],[]).append(p)
    renamed=[]; uc=set(); ud=set()
    for op in deleted:
        target=next((p for p in byhash.get(a[op]["sha256"],[]) if p not in uc),None)
        if target:
            renamed.append({"from":op,"to":target,"sha256":a[op]["sha256"]}); uc.add(target); ud.add(op)
    return {"created":[p for p in created if p not in uc],
            "deleted":[p for p in deleted if p not in ud],
            "modified":modified,"renamed":renamed}

def has_changes(c): return any(c.get(k) for k in ("created","deleted","modified","renamed"))

def save_json(data,path):
    p=Path(path).expanduser(); p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(json.dumps(data,indent=2),encoding="utf-8")

def load_json(path): return json.loads(Path(path).expanduser().read_text(encoding="utf-8"))

def format_events(c):
    e=[("CREATED",p,None) for p in c.get("created",[])]
    e += [("DELETED",p,None) for p in c.get("deleted",[])]
    e += [("MODIFIED",p,None) for p in c.get("modified",[])]
    e += [("RENAMED",r["from"],r["to"]) for r in c.get("renamed",[])]
    return e

def init_db(db):
    p=Path(db).expanduser(); p.parent.mkdir(parents=True,exist_ok=True)
    with sqlite3.connect(p) as con:
        con.execute("""CREATE TABLE IF NOT EXISTS events(
        id INTEGER PRIMARY KEY AUTOINCREMENT,timestamp TEXT NOT NULL,event_type TEXT NOT NULL,
        path TEXT NOT NULL,new_path TEXT,monitored_root TEXT NOT NULL)""")

def log_changes(db,c,root):
    init_db(db); ids=[]
    with sqlite3.connect(Path(db).expanduser()) as con:
        for kind,path,new_path in format_events(c):
            cur=con.execute("INSERT INTO events(timestamp,event_type,path,new_path,monitored_root) VALUES(?,?,?,?,?)",
                (utc_now(),kind,path,new_path,str(Path(root).expanduser().resolve())))
            ids.append(cur.lastrowid)
    return ids

def get_events(db,limit=50):
    p=Path(db).expanduser()
    if not p.exists(): return []
    init_db(p)
    with sqlite3.connect(p) as con:
        con.row_factory=sqlite3.Row
        rows=con.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?",(limit,)).fetchall()
    return [dict(r) for r in rows]
