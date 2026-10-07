# ise-health-audit

Read-only health and certificate-expiry audit for Cisco ISE. One command tells you which nodes are down, whether admin HA exists, and which system and trusted certificates are expired or about to expire, before an expired EAP or admin certificate takes authentication down.

## What it checks

| Check | Severity |
|---|---|
| Node not reporting `Connected` | critical |
| No Primary Admin node | critical |
| No Secondary Admin node (no admin HA) | warning |
| System certificate expired, or within 30 days | critical |
| System certificate within 60 days | warning |
| Self-signed certificate in use for Admin or EAP | warning |
| Trusted certificate expired or expiring | critical / warning |

Windows are set at the top of `ise_audit.py`.

## Safety

GET requests only, against three ISE OpenAPI endpoints:

```
GET /api/v1/deployment/node
GET /api/v1/certs/system-certificate/{hostname}
GET /api/v1/certs/trusted-certificate
```

Nothing is created, changed or deleted. Credentials come from `ISE_USERNAME` / `ISE_PASSWORD` or a prompt and are never written to disk.

## Requirements

- Cisco ISE with OpenAPI enabled (Administration > System > Settings > API Settings > API Service Settings). It is off by default.
- An admin account with read access to the OpenAPI. Use a dedicated read-only account rather than a full admin.
- Python 3.9+ and `pip install -r requirements.txt`.

## Usage

```bash
python ise_audit.py --pan ise-pan1.example.com --ca-bundle corp-ca.pem
python ise_audit.py --pan 192.0.2.10 --insecure --csv findings.csv     # lab only
python ise_audit.py --offline saved-json/                              # no ISE access needed
```

Offline mode reads saved API output (`nodes.json`, `trusted.json`, `system_<hostname>.json`), so a client can run three GET calls themselves and hand you the JSON without granting access.

Exit codes: `0` clean, `1` findings, `2` error, so it schedules cleanly and alerts on non-zero.

## Status

Tested offline against the response formats in Cisco's published OpenAPI documentation. If a field differs on your ISE version, open an issue with a redacted sample.

## Tests

```bash
pip install pytest && python -m pytest
```

## License

MIT. See LICENSE. Security reports: see SECURITY.md.