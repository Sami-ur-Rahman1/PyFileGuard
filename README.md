# 🛡️ PyFileGuard

A lightweight Python **File Integrity Monitoring (FIM)** tool for defensive security, DFIR labs, and learning. PyFileGuard creates a trusted SHA-256 baseline and detects subsequent file creation, deletion, modification, and best-effort renames.

## Features
- Recursive directory inventory
- SHA-256 integrity hashes
- Detects created, deleted, and modified files
- Best-effort rename detection using matching content hashes
- Continuous monitoring mode
- JSON output for automation
- Optional baseline refresh after detected changes
- Zero third-party runtime dependencies

## Install
```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows: .venv\\Scripts\\activate
pip install -e .
```

## Usage
Create a baseline:
```bash
pyfileguard baseline ./important-files -o baseline.json
```

Check integrity:
```bash
pyfileguard check ./important-files -b baseline.json
```

Machine-readable output:
```bash
pyfileguard check ./important-files -b baseline.json --json
```

Continuous monitoring:
```bash
pyfileguard monitor ./important-files -b baseline.json --interval 5
```

## Example
```text
[MODIFIED] config/app.conf
[CREATED] uploads/new.txt
[RENAMED] docs/old.txt -> docs/archive.txt
[DELETED] temp/debug.log
```

## Architecture
`core.py` handles hashing, snapshots, persistence, and comparison. `cli.py` exposes baseline/check/monitor workflows. Baselines are portable JSON files containing relative paths, SHA-256 hashes, size, and modification metadata.

## Security notes
A baseline should be created from a directory you already trust. For meaningful monitoring, protect the baseline itself with appropriate OS permissions and ideally store a copy separately. PyFileGuard reports integrity changes; it does not automatically decide whether a change is malicious.

## Roadmap
- Ignore patterns / `.pyfileguardignore`
- SQLite event history
- Signed baselines
- Email/webhook alerts
- Rich terminal dashboard
- HTML/CSV incident reports
- Cross-platform service/daemon mode

## Testing
```bash
pip install pytest
pytest -q
```

## Responsible use
Designed for systems and files you own or are authorized to monitor.

## License
MIT
