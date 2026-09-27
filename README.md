# PyFileGuard

**A FortiX CyberTech Product**

**Defend. Secure. Fortify.**

PyFileGuard is a lightweight Python SHA-256 file integrity monitoring tool.

## v0.3.0
- FortiX CyberTech product identity
- Multi-directory baselines
- Monitoring profiles
- Custom ignore rules
- Rule-based severity levels
- Searchable SQLite event history
- JSON/CSV report export
- Optional HMAC-SHA256 baseline authentication
- Duplicate-free monitoring
- CREATED / MODIFIED / DELETED / RENAMED detection

Severity labels prioritize review; they do not determine that a change is malicious.

## Install
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
pyfileguard
```

## Examples
```bash
pyfileguard baseline /etc/nginx /var/www -o baseline.json --ignore "*.log"
pyfileguard baseline ./important -o baseline.json --protect
pyfileguard check -b baseline.json
pyfileguard monitor -b baseline.json --interval 5
pyfileguard history --severity HIGH
pyfileguard export report.csv --format csv
```
