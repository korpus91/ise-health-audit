#!/usr/bin/env python3
"""
ise-health-audit: read-only health and certificate-expiry audit for Cisco ISE.

Uses only GET calls on the ISE OpenAPI (ISE 3.1+ with OpenAPI enabled):
  GET /api/v1/deployment/node
  GET /api/v1/certs/system-certificate/{hostname}
  GET /api/v1/certs/trusted-certificate

Checks
  - every node reports nodeStatus Connected
  - a Primary and Secondary Admin node exist (admin HA)
  - system certificates expiring within warn/critical windows, or expired
  - self-signed certificates in use for Admin or EAP
  - trusted certificates that are expired or expiring

Offline mode (--offline DIR) audits saved JSON instead of a live PAN, so a
client can hand you API output without giving you access.

Exit codes: 0 clean, 1 findings, 2 error.
"""
import argparse
import csv
import datetime as dt
import getpass
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

WARN_DAYS = 60      # EDIT: certificate expiry warning window
CRITICAL_DAYS = 30  # EDIT: certificate expiry critical window

_TZ = re.compile(r"\s[A-Z]{2,5}\s(?=\d{4}$)")


@dataclass
class Finding:
    severity: str
    scope: str
    issue: str
    detail: str


def parse_ise_date(s: str) -> dt.datetime:
    """ISE returns e.g. 'Thu Mar 29 16:24:12 CST 2029'. The zone token is dropped (day-level precision)."""
    return dt.datetime.strptime(_TZ.sub(" ", s.strip()), "%a %b %d %H:%M:%S %Y")


def days_left(expiry: str, today: dt.datetime) -> int:
    return (parse_ise_date(expiry) - today).days


class Source:
    def nodes(self): ...
    def system_certs(self, host): ...
    def trusted_certs(self): ...


class Live(Source):
    def __init__(self, pan, user, pwd, verify):
        import requests  # lazy: offline mode needs no dependencies
        self.s = requests.Session()
        self.s.auth = (user, pwd)
        self.s.headers.update({"Accept": "application/json"})
        self.s.verify = verify
        self.base = f"https://{pan}"

    def _get(self, path, params=None):
        r = self.s.get(self.base + path, params=params, timeout=30)
        r.raise_for_status()
        return r.json().get("response", [])

    def nodes(self):
        return self._get("/api/v1/deployment/node")

    def system_certs(self, host):
        return self._get(f"/api/v1/certs/system-certificate/{host}")

    def trusted_certs(self):
        out, page = [], 1
        while True:
            batch = self._get("/api/v1/certs/trusted-certificate", {"page": page, "size": 100})
            out.extend(batch)
            if len(batch) < 100:
                return out
            page += 1


class Offline(Source):
    """Directory with nodes.json, trusted.json and system_<hostname>.json (raw API output)."""
    def __init__(self, d: Path):
        self.d = d

    def _load(self, name):
        p = self.d / name
        if not p.exists():
            return []
        data = json.loads(p.read_text(encoding="utf-8"))
        return data.get("response", data) if isinstance(data, dict) else data

    def nodes(self):
        return self._load("nodes.json")

    def system_certs(self, host):
        return self._load(f"system_{host}.json")

    def trusted_certs(self):
        return self._load("trusted.json")


def cert_finding(scope, cert, today, label):
    name = cert.get("friendlyName") or cert.get("issuedTo") or cert.get("id", "?")
    exp = cert.get("expirationDate")
    if not exp:
        return None
    try:
        left = days_left(exp, today)
    except ValueError:
        return Finding("warning", scope, f"{label} date unreadable", f"{name}: {exp}")
    if left < 0:
        return Finding("critical", scope, f"{label} expired", f"{name}: expired {-left} days ago")
    if left <= CRITICAL_DAYS:
        return Finding("critical", scope, f"{label} expiring", f"{name}: {left} days left ({exp})")
    if left <= WARN_DAYS:
        return Finding("warning", scope, f"{label} expiring", f"{name}: {left} days left ({exp})")
    return None


def audit(src: Source, today=None) -> list:
    today = today or dt.datetime.now()
    f = []
    nodes = src.nodes()
    if not nodes:
        return [Finding("critical", "deployment", "No nodes returned", "check OpenAPI is enabled and the account has read access")]

    roles = {r for n in nodes for r in n.get("roles", [])}
    if "PrimaryAdmin" not in roles:
        f.append(Finding("critical", "deployment", "No Primary Admin node", "roles seen: " + (", ".join(sorted(roles)) or "none")))
    if "SecondaryAdmin" not in roles and len(nodes) > 1:
        f.append(Finding("warning", "deployment", "No Secondary Admin node", "admin HA is not configured"))

    for n in nodes:
        host = n.get("hostname", "?")
        status = n.get("nodeStatus", "unknown")
        if status != "Connected":
            f.append(Finding("critical", host, "Node not connected", f"nodeStatus={status}"))
        for c in src.system_certs(host):
            x = cert_finding(host, c, today, "System certificate")
            if x:
                f.append(x)
            used = (c.get("usedBy") or "")
            if c.get("selfSigned") and re.search(r"\b(Admin|EAP)", used):
                f.append(Finding("warning", host, "Self-signed certificate in use",
                                 f"{c.get('friendlyName', '?')} used by: {used}"))

    for c in src.trusted_certs():
        x = cert_finding("trusted store", c, today, "Trusted certificate")
        if x:
            f.append(x)

    f.sort(key=lambda x: (x.severity != "critical", x.scope, x.issue))
    return f


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Read-only Cisco ISE health and certificate audit")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--pan", help="Primary Admin node hostname or IP")
    g.add_argument("--offline", type=Path, help="directory of saved API JSON")
    p.add_argument("--ca-bundle", help="CA bundle to verify the PAN certificate")
    p.add_argument("--insecure", action="store_true", help="skip TLS verification (lab use only)")
    p.add_argument("--csv", help="also write findings to CSV")
    a = p.parse_args(argv)

    try:
        if a.offline:
            src = Offline(a.offline)
        else:
            user = os.environ.get("ISE_USERNAME") or input("ISE username: ")
            pwd = os.environ.get("ISE_PASSWORD") or getpass.getpass("ISE password: ")
            verify = False if a.insecure else (a.ca_bundle or True)
            if a.insecure:
                import urllib3
                urllib3.disable_warnings()
            src = Live(a.pan, user, pwd, verify)
        findings = audit(src)
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    print(f"{len(findings)} findings")
    for x in findings:
        print(f"[{x.severity.upper():8}] {x.scope:24} {x.issue}: {x.detail}")
    if a.csv:
        with open(a.csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["severity", "scope", "issue", "detail"])
            w.writerows([[x.severity, x.scope, x.issue, x.detail] for x in findings])
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())