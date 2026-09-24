# PyFileGuard v0.2.0

A lightweight Python SHA-256 File Integrity Monitoring (FIM) tool.

## v0.2.0
- Numbered interactive menu (`pyfileguard`)
- Manual path entry
- Monitor events are no longer repeated every polling cycle
- Timestamped monitor events
- SQLite event history (`~/.pyfileguard/events.db`)
- Common cache/temp files ignored by default
- Existing CLI commands retained
- Expanded tests

## Install
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Interactive mode
```bash
pyfileguard
```

Options: Create Baseline, Check Integrity, Start Monitor Mode, View Event History, Help, Exit.

## CLI
```bash
pyfileguard baseline ./files -o baseline.json
pyfileguard check ./files -b baseline.json
pyfileguard monitor ./files -b baseline.json --interval 5
pyfileguard history
```

## Tests
```bash
pip install pytest
pytest -q
```

An integrity alert means a file changed; it does not by itself prove malicious activity.

## License
MIT
