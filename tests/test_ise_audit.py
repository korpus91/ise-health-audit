import datetime as dt
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import ise_audit as ia  # noqa: E402

TODAY = dt.datetime(2026, 10, 7)


def issues():
    return {(f.scope, f.issue): f for f in ia.audit(ia.Offline(HERE / "fixtures"), today=TODAY)}


def test_date_parsing_drops_zone():
    assert ia.parse_ise_date("Thu Mar 29 16:24:12 CST 2029") == dt.datetime(2029, 3, 29, 16, 24, 12)


def test_disconnected_node_is_critical():
    assert issues()[("ise-psn1", "Node not connected")].severity == "critical"


def test_missing_secondary_admin_warns():
    assert ("deployment", "No Secondary Admin node") in issues()


def test_cert_inside_warn_window():
    assert issues()[("ise-pan1", "System certificate expiring")].severity == "warning"  # 38 days


def test_cert_outside_windows_is_clean():
    assert ("ise-psn1", "System certificate expiring") not in issues()  # 75 days


def test_expired_trusted_cert_is_critical():
    assert issues()[("trusted store", "Trusted certificate expired")].severity == "critical"


def test_self_signed_admin_cert_flagged():
    assert ("ise-pan1", "Self-signed certificate in use") in issues()


def test_cli_offline_exit_and_csv(tmp_path):
    out = tmp_path / "f.csv"
    assert ia.main(["--offline", str(HERE / "fixtures"), "--csv", str(out)]) == 1
    assert out.read_text().splitlines()[0] == "severity,scope,issue,detail"