from __future__ import annotations
import hashlib, json, os
from pathlib import Path
from datetime import datetime, timezone


def sha256(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(chunk_size), b''):
            h.update(chunk)
    return h.hexdigest()


def snapshot(root: Path) -> dict:
    root = root.resolve()
    files = {}
    for p in sorted(root.rglob('*')):
        if p.is_file():
            try:
                st = p.stat()
                files[str(p.relative_to(root))] = {
                    'sha256': sha256(p), 'size': st.st_size,
                    'mtime_ns': st.st_mtime_ns,
                }
            except (OSError, PermissionError):
                continue
    return {'root': str(root), 'created_at': datetime.now(timezone.utc).isoformat(), 'files': files}


def diff(old: dict, new: dict) -> dict:
    a, b = old.get('files', {}), new.get('files', {})
    ak, bk = set(a), set(b)
    created = sorted(bk - ak)
    deleted = sorted(ak - bk)
    modified = sorted(k for k in ak & bk if a[k]['sha256'] != b[k]['sha256'])

    # Best-effort rename detection: same content hash disappeared/reappeared.
    deleted_by_hash = {}
    for k in deleted:
        deleted_by_hash.setdefault(a[k]['sha256'], []).append(k)
    created_by_hash = {}
    for k in created:
        created_by_hash.setdefault(b[k]['sha256'], []).append(k)
    renamed = []
    for digest in set(deleted_by_hash) & set(created_by_hash):
        while deleted_by_hash[digest] and created_by_hash[digest]:
            renamed.append({'from': deleted_by_hash[digest].pop(0), 'to': created_by_hash[digest].pop(0), 'sha256': digest})
    renamed_from = {r['from'] for r in renamed}; renamed_to = {r['to'] for r in renamed}
    created = [k for k in created if k not in renamed_to]
    deleted = [k for k in deleted if k not in renamed_from]
    return {'created': created, 'deleted': deleted, 'modified': modified, 'renamed': renamed}


def save_json(data: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding='utf-8')


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding='utf-8'))
