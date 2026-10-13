"""`inputs.state_revision` is optional and informational (SPEC.md section 2).

It was required but compared against nothing. It is now demoted: the checker
must accept packets with it absent, present with any string, or present but
empty, and must never emit `missing_field:inputs.state_revision`.
"""
import datetime as dt
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import handoff_check as hc

ROOT = Path(__file__).resolve().parents[1]
AT = dt.datetime(2026, 9, 30, 20, 0, tzinfo=dt.timezone.utc)


def base_packet():
    return json.loads((ROOT / "examples" / "valid.json").read_text())


def registry():
    return json.loads((ROOT / "examples" / "registry.json").read_text())


def run(packet, ledger=None):
    ok, reasons = hc.validate(packet, registry=registry(), ledger=ledger or {},
                              workspace=ROOT, at=AT)
    return ok, {r["code"] for r in reasons}


def test_missing_state_revision_accepted():
    p = base_packet()
    del p["handoff"]["inputs"]["state_revision"]
    ok, codes = run(p)
    assert ok and "missing_field:inputs.state_revision" not in codes


def test_state_revision_any_string_accepted():
    p = base_packet()
    p["handoff"]["inputs"]["state_revision"] = "whatever-the-sender-wants"
    ok, codes = run(p)
    assert ok and "missing_field:inputs.state_revision" not in codes


def test_empty_state_revision_accepted():
    # Informational field: the checker does not police its content.
    p = base_packet()
    p["handoff"]["inputs"]["state_revision"] = ""
    ok, codes = run(p)
    assert ok and "missing_field:inputs.state_revision" not in codes


def test_other_required_fields_still_checked():
    # The demotion must not loosen anything else.
    p = base_packet()
    del p["handoff"]["inputs"]
    ok, codes = run(p)
    assert not ok and "missing_field:inputs" in codes
