# PyFileGuard v0.3.0 Technical Notes

**PyFileGuard — A FortiX CyberTech Product**  
**Defend. Secure. Fortify.**

## Modules
- `core.py`: SHA-256 scanning, baselines, comparison, HMAC authentication.
- `database.py`: SQLite event storage/filtering.
- `profiles.py`: reusable monitoring profile storage.
- `reporting.py`: JSON/CSV export.
- `severity.py`: transparent rule-based prioritization.
- `cli.py`: interactive and command-line interfaces.

## Baseline protection
Optional HMAC-SHA256 authentication detects baseline alteration. The secret is not stored in the baseline and must be retained separately.

## Validation
Before release, test branding/version, multi-directory baselines, ignores, all four change types, severity, monitor deduplication, history filters, report export, profiles, baseline authentication/tamper detection, legacy CLI behavior, and pytest.
