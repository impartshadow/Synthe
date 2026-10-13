"""Ledger integrity binding v2: HMAC-sealed hash chain + out-of-cache anchor.

Covers the three reviewer-reproduced attacks (older sealed snapshot,
forged empty sealed ledger, deleted file), the HMAC key behavior
(including rotation and key-state mismatch), the anchor state machine
(rollback / diverged / anchor-unavailable / bootstrap), legacy adoption
with NO hard-fail, the ~synthe reserved namespace, and the SQLite backend.
"""
import copy
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
import handoff_check as hc  # noqa: E402

V3 = ROOT / "examples" / "v03"
WS = V3 / "workspace"
MARKER = "~synthe"


@pytest.fixture(autouse=True)
def clean_ledger_env(monkeypatch):
    """Every test starts with no anchor/key env; warnings reset."""
    for var in (hc.LEDGER_HMAC_KEY_ENV, hc.LEDGER_HMAC_PREV_ENV,
                hc.LEDGER_ANCHOR_ENV, hc.LEDGER_ANCHOR_REQUIRED_ENV,
                hc.LEDGER_BOOTSTRAP_ENV):
        monkeypatch.delenv(var, raising=False)
    hc._warned.clear()


def packet(suffix, key=None):
    p = json.loads((V3 / "packets" / "valid-signed.json").read_text())
    p.pop("signature", None)
    h = p["handoff"]
    h["id"] = f"h-{suffix}"
    h["trace_id"] = f"t-{suffix}"
    h["idempotency_key"] = key if key is not None else f"k-{suffix}"
    h.pop("planned_actions", None)
    h["scope"].setdefault("owned_paths", ["rules/**"])
    h["acceptance"].setdefault("output_schema", "verdict_pack.v1")
    h["authority"].setdefault("budget", {"tokens": 50000, "usd": 2, "minutes": 30})
    return p


def accept(ledger, suffix, key=None):
    p = packet(suffix, key=key)
    v = hc.check(p, registry=None, ledger_path=ledger, workspace=WS)
    assert v["decision"] == "ACCEPT", v
    return p


def read_ledger(ledger):
    return json.loads(Path(ledger).read_text())


def header_of(ledger):
    return read_ledger(ledger)[MARKER]


def set_anchor_from_ledger(monkeypatch, ledger, required=True):
    hdr = header_of(ledger)
    anchor = f"{hdr['chain_seq']}:{hdr['chain_head']}"
    monkeypatch.setenv(hc.LEDGER_ANCHOR_ENV, anchor)
    if required:
        monkeypatch.setenv(hc.LEDGER_ANCHOR_REQUIRED_ENV, "1")
    return anchor


# --- sealing basics -------------------------------------------------------

def test_genesis_seal_on_first_write(tmp_path):
    ledger = tmp_path / "ledger.json"
    accept(ledger, "g1")
    hdr = header_of(ledger)
    assert hdr["chain_format"] == "synthe-ledger-chain/v2"
    assert hdr["chain_seq"] == 1
    assert hdr["chain_prev"] == hc.LEDGER_GENESIS_PREV
    assert hdr["chain_keyed"] is False  # no key configured -> checksum mode
    assert len(hdr["chain_head"]) == 64


def test_chain_extends_and_links_prev(tmp_path):
    ledger = tmp_path / "ledger.json"
    accept(ledger, "c1")
    head1 = header_of(ledger)["chain_head"]
    accept(ledger, "c2")
    hdr = header_of(ledger)
    assert hdr["chain_seq"] == 2
    assert hdr["chain_prev"] == head1
    # verify the seal recomputes
    ok, _code, _msg, _hdr, _used = hc.verify_ledger_seal(read_ledger(ledger))
    assert ok


def test_tampered_entry_fails_closed(tmp_path):
    ledger = tmp_path / "ledger.json"
    accept(ledger, "t1")
    data = read_ledger(ledger)
    data["k-t1"]["state"] = "COMPLETED"  # hand edit
    Path(ledger).write_text(json.dumps(data))
    v = hc.check(packet("t2"), registry=None, ledger_path=ledger, workspace=WS)
    assert v["decision"] == "REJECT"
    assert v["reasons"][0]["code"] == "ledger_corrupt"


def test_truncated_file_fails_closed(tmp_path):
    ledger = tmp_path / "ledger.json"
    accept(ledger, "t1")
    Path(ledger).write_text(Path(ledger).read_text()[:40])  # torn write
    v = hc.check(packet("t2"), registry=None, ledger_path=ledger, workspace=WS)
    assert v["reasons"][0]["code"] == "ledger_corrupt"


def test_non_object_file_fails_closed(tmp_path):
    ledger = tmp_path / "ledger.json"
    Path(ledger).write_text("[1, 2, 3]")
    v = hc.check(packet("t1"), registry=None, ledger_path=ledger, workspace=WS)
    assert v["reasons"][0]["code"] == "ledger_corrupt"


# --- HMAC key -------------------------------------------------------------

def test_hmac_key_seals_keyed_chain(tmp_path, monkeypatch):
    monkeypatch.setenv(hc.LEDGER_HMAC_KEY_ENV, "s3cret")
    ledger = tmp_path / "ledger.json"
    accept(ledger, "h1")
    hdr = header_of(ledger)
    assert hdr["chain_keyed"] is True
    # a forged seal made without the key does not verify
    data = read_ledger(ledger)
    data[MARKER]["chain_head"] = "00" * 32
    Path(ledger).write_text(json.dumps(data))
    v = hc.check(packet("h2"), registry=None, ledger_path=ledger, workspace=WS)
    assert v["reasons"][0]["code"] == "ledger_corrupt"


def test_keyed_ledger_loaded_without_key_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv(hc.LEDGER_HMAC_KEY_ENV, "s3cret")
    ledger = tmp_path / "ledger.json"
    accept(ledger, "h1")
    monkeypatch.delenv(hc.LEDGER_HMAC_KEY_ENV)
    v = hc.check(packet("h2"), registry=None, ledger_path=ledger, workspace=WS)
    assert v["decision"] == "REJECT"
    assert v["reasons"][0]["code"] == "ledger_corrupt"


def test_unkeyed_ledger_loaded_with_key_fails_closed(tmp_path, monkeypatch):
    ledger = tmp_path / "ledger.json"
    accept(ledger, "h1")  # sealed without a key
    monkeypatch.setenv(hc.LEDGER_HMAC_KEY_ENV, "s3cret")
    v = hc.check(packet("h2"), registry=None, ledger_path=ledger, workspace=WS)
    assert v["reasons"][0]["code"] == "ledger_corrupt"


def test_key_rotation_heals_on_next_save(tmp_path, monkeypatch):
    monkeypatch.setenv(hc.LEDGER_HMAC_KEY_ENV, "old-key")
    ledger = tmp_path / "ledger.json"
    accept(ledger, "r1")
    monkeypatch.setenv(hc.LEDGER_HMAC_KEY_ENV, "new-key")
    monkeypatch.setenv(hc.LEDGER_HMAC_PREV_ENV, "old-key")
    v = hc.check(packet("r2"), registry=None, ledger_path=ledger, workspace=WS)
    assert v["decision"] == "ACCEPT"  # previous key accepted for verification
    monkeypatch.delenv(hc.LEDGER_HMAC_PREV_ENV)
    v = hc.check(packet("r3"), registry=None, ledger_path=ledger, workspace=WS)
    assert v["decision"] == "ACCEPT"  # re-sealed with the current key


# --- the three attacks (full configuration: key + anchor) -----------------


def test_attack1_older_snapshot_is_rollback(tmp_path, monkeypatch):
    monkeypatch.setenv(hc.LEDGER_HMAC_KEY_ENV, "s3cret")
    ledger = tmp_path / "ledger.json"
    accept(ledger, "a1")
    snapshot = Path(ledger).read_bytes()
    p2 = accept(ledger, "a2")
    hc.complete(p2, ledger)
    set_anchor_from_ledger(monkeypatch, ledger)  # anchor at the newest head
    Path(ledger).write_bytes(snapshot)  # stale cache restores the old copy
    v = hc.check(packet("a3"), registry=None, ledger_path=ledger, workspace=WS)
    assert v["decision"] == "REJECT"
    assert v["reasons"][0]["code"] == "ledger_rollback"
    # and the forgotten claim cannot be re-presented
    v = hc.check(p2, registry=None, ledger_path=ledger, workspace=WS)
    assert v["reasons"][0]["code"] == "ledger_rollback"


def test_attack2_forged_empty_sealed_ledger(tmp_path, monkeypatch):
    monkeypatch.setenv(hc.LEDGER_HMAC_KEY_ENV, "s3cret")
    ledger = tmp_path / "ledger.json"
    p1 = accept(ledger, "a1")
    hc.complete(p1, ledger)
    set_anchor_from_ledger(monkeypatch, ledger)
    forged = {MARKER: {"chain_format": "synthe-ledger-chain/v2", "chain_seq": 99,
                       "chain_prev": "00" * 32, "chain_head": "ff" * 32,
                       "chain_keyed": True}}
    Path(ledger).write_text(json.dumps(forged))
    v = hc.check(p1, registry=None, ledger_path=ledger, workspace=WS)
    assert v["decision"] == "REJECT"
    assert v["reasons"][0]["code"] == "ledger_corrupt"


def test_attack2b_bare_swap_under_anchor_is_rollback(tmp_path, monkeypatch):
    monkeypatch.setenv(hc.LEDGER_HMAC_KEY_ENV, "s3cret")
    ledger = tmp_path / "ledger.json"
    p1 = accept(ledger, "a1")
    hc.complete(p1, ledger)
    set_anchor_from_ledger(monkeypatch, ledger)
    Path(ledger).write_text("{}")
    v = hc.check(p1, registry=None, ledger_path=ledger, workspace=WS)
    assert v["reasons"][0]["code"] == "ledger_rollback"


def test_attack3_deleted_file_is_rollback(tmp_path, monkeypatch):
    monkeypatch.setenv(hc.LEDGER_HMAC_KEY_ENV, "s3cret")
    ledger = tmp_path / "ledger.json"
    p1 = accept(ledger, "a1")
    hc.complete(p1, ledger)
    set_anchor_from_ledger(monkeypatch, ledger)
    Path(ledger).unlink()
    v = hc.check(p1, registry=None, ledger_path=ledger, workspace=WS)
    assert v["decision"] == "REJECT"
    assert v["reasons"][0]["code"] == "ledger_rollback"


def test_anchor_diverged_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv(hc.LEDGER_HMAC_KEY_ENV, "s3cret")
    ledger = tmp_path / "ledger.json"
    accept(ledger, "d1")
    hdr = header_of(ledger)
    monkeypatch.setenv(hc.LEDGER_ANCHOR_ENV, f"{hdr['chain_seq']}:{'ab' * 32}")
    monkeypatch.setenv(hc.LEDGER_ANCHOR_REQUIRED_ENV, "1")
    v = hc.check(packet("d2"), registry=None, ledger_path=ledger, workspace=WS)
    assert v["reasons"][0]["code"] == "ledger_diverged"


def test_anchor_extend_is_allowed(tmp_path, monkeypatch):
    """A ledger NEWER than the anchor (publish lagged) still loads: the
    anchor must be matched or extended, never rolled back."""
    ledger = tmp_path / "ledger.json"
    accept(ledger, "e1")
    hdr = header_of(ledger)
    monkeypatch.setenv(hc.LEDGER_ANCHOR_ENV, f"{hdr['chain_seq']}:{hdr['chain_head']}")
    monkeypatch.setenv(hc.LEDGER_ANCHOR_REQUIRED_ENV, "1")
    accept(ledger, "e2")  # seq advances past the anchor: allowed
    v = hc.check(packet("e3"), registry=None, ledger_path=ledger, workspace=WS)
    assert v["decision"] == "ACCEPT"


def test_anchor_unavailable_fails_closed_when_required(tmp_path, monkeypatch):
    ledger = tmp_path / "ledger.json"
    accept(ledger, "u1")
    monkeypatch.setenv(hc.LEDGER_ANCHOR_REQUIRED_ENV, "1")
    v = hc.check(packet("u2"), registry=None, ledger_path=ledger, workspace=WS)
    assert v["reasons"][0]["code"] == "ledger_anchor_unavailable"


def test_bootstrap_recovers_after_eviction(tmp_path, monkeypatch):
    ledger = tmp_path / "ledger.json"
    accept(ledger, "b1")
    anchor = set_anchor_from_ledger(monkeypatch, ledger)
    Path(ledger).unlink()  # total cache eviction
    v = hc.check(packet("b2"), registry=None, ledger_path=ledger, workspace=WS)
    assert v["reasons"][0]["code"] == "ledger_rollback"
    monkeypatch.setenv(hc.LEDGER_BOOTSTRAP_ENV, "1")
    v = hc.check(packet("b2"), registry=None, ledger_path=ledger, workspace=WS)
    assert v["decision"] == "ACCEPT"
    assert header_of(ledger)["chain_seq"] == 1  # chain restarted
    assert anchor != f"1:{header_of(ledger)['chain_head']}"  # new head to publish


# --- degrade mode: no key, no anchor --------------------------------------

def test_legacy_ledger_loads_with_warning_not_failure(tmp_path, capsys):
    """No --adopt-legacy step: a pre-chain ledger is adopted in place."""
    ledger = tmp_path / "ledger.json"
    Path(ledger).write_text(json.dumps({"old-key": {"state": "COMPLETED",
                                                    "handoff_id": "h-old"}}))
    p = packet("n1")
    v = hc.check(p, registry=None, ledger_path=ledger, workspace=WS)
    assert v["decision"] == "ACCEPT", v
    data = read_ledger(ledger)
    assert data["old-key"]["state"] == "COMPLETED"  # entries preserved
    assert data[MARKER]["chain_seq"] >= 1  # sealed as a new chain
    assert "adopting" in capsys.readouterr().err


def test_degrade_mode_warns_but_loads(tmp_path, capsys):
    ledger = tmp_path / "ledger.json"
    accept(ledger, "w1")
    v = hc.check(packet("w2"), registry=None, ledger_path=ledger, workspace=WS)
    assert v["decision"] == "ACCEPT"
    assert "SYNTHE_LEDGER_ANCHOR" in capsys.readouterr().err


# --- reserved namespace ----------------------------------------------------

def test_tilde_idempotency_key_rejected(tmp_path):
    ledger = tmp_path / "ledger.json"
    v = hc.check(packet("r1", key="~synthe-evil"), registry=None,
                 ledger_path=ledger, workspace=WS)
    assert v["decision"] == "REJECT"
    assert v["reasons"][0]["code"] == "reserved_idempotency_key"
    # the header cannot be clobbered by a claim: a later legit claim seals
    # a well-formed chain header under "~synthe"
    accept(ledger, "r2")
    hdr = header_of(ledger)
    assert hdr["chain_format"] == "synthe-ledger-chain/v2"


def test_tilde_key_rejected_even_as_header_name(tmp_path):
    ledger = tmp_path / "ledger.json"
    v = hc.check(packet("r1", key="~synthe"), registry=None,
                 ledger_path=ledger, workspace=WS)
    assert v["reasons"][0]["code"] == "reserved_idempotency_key"


def test_underscore_keys_still_allowed(tmp_path):
    """Only '~' is reserved; '_'-prefixed keys are ordinary claims."""
    ledger = tmp_path / "ledger.json"
    p = accept(ledger, "u1", key="_private_key")
    assert read_ledger(ledger)["_private_key"]["state"] == "RESERVED"


def test_unknown_tilde_fields_preserved_across_seals(tmp_path):
    """Forward-compat: other tooling's '~synthe' fields survive re-sealing.

    Only the security-relevant triple (chain_seq, chain_prev, entries) plus
    the key-state flag is MAC-bound; informational header fields are
    preserved verbatim and are not tamper-evident (tampering with them gains
    an attacker nothing: seq/prev/head/keyed cannot be altered without
    breaking the seal)."""
    ledger = tmp_path / "ledger.json"
    accept(ledger, "f1")
    # simulate another tool's marker fields, added through the seal API
    data = read_ledger(ledger)
    data[MARKER]["ledger_id"] = "abc123"
    hc.seal_ledger(data)
    Path(ledger).write_text(json.dumps(data))
    v = hc.check(packet("f2"), registry=None, ledger_path=ledger, workspace=WS)
    assert v["decision"] == "ACCEPT", v
    assert read_ledger(ledger)[MARKER]["ledger_id"] == "abc123"


def test_path_conflicts_skip_header(tmp_path):
    """exclusive_paths scans must not trip over the '~synthe' header."""
    ledger = tmp_path / "ledger.json"
    p1 = packet("p1")
    p1["handoff"]["scope"]["owned_paths"] = ["rules/**"]
    v = hc.check(p1, registry=None, ledger_path=ledger, workspace=WS)
    assert v["decision"] == "ACCEPT", v
    p2 = packet("p2")
    p2["handoff"]["scope"]["owned_paths"] = ["other/**"]
    v = hc.check(p2, registry=None, ledger_path=ledger, workspace=WS)
    assert v["decision"] == "ACCEPT", v


# --- operator CLI ----------------------------------------------------------

def test_init_ledger_new_and_noop(tmp_path):
    ledger = tmp_path / "init.json"
    ok, msg = hc.init_ledger(ledger)
    assert ok and "genesis" in msg
    assert header_of(ledger)["chain_seq"] == 1
    ok, msg = hc.init_ledger(ledger)
    assert ok and "no-op" in msg
    assert header_of(ledger)["chain_seq"] == 1  # no bump on no-op


def test_init_ledger_adopts_legacy(tmp_path):
    ledger = tmp_path / "legacy.json"
    Path(ledger).write_text(json.dumps({"k": {"state": "COMPLETED"}}))
    ok, msg = hc.init_ledger(ledger)
    assert ok and "adopted 1" in msg
    data = read_ledger(ledger)
    assert data["k"]["state"] == "COMPLETED"
    assert data[MARKER]["chain_seq"] == 1


def test_init_ledger_refuses_corrupt(tmp_path):
    ledger = tmp_path / "bad.json"
    Path(ledger).write_text('{"not": "a ledger", "unclosed": ')
    ok, msg = hc.init_ledger(ledger)
    assert not ok


def test_init_ledger_refuses_under_anchor(tmp_path, monkeypatch):
    ledger = tmp_path / "nope.json"
    monkeypatch.setenv(hc.LEDGER_ANCHOR_ENV, "7:deadbeef")
    monkeypatch.setenv(hc.LEDGER_ANCHOR_REQUIRED_ENV, "1")
    ok, msg = hc.init_ledger(ledger)
    assert not ok and "ledger_rollback" in msg


def test_ledger_head_cli(tmp_path):
    ledger = tmp_path / "ledger.json"
    assert hc.ledger_head(ledger) == ""
    accept(ledger, "lh1")
    head = hc.ledger_head(ledger)
    hdr = header_of(ledger)
    assert head == f"{hdr['chain_seq']}:{hdr['chain_head']}"
    Path(ledger).write_text("{}")
    assert hc.ledger_head(ledger) == ""  # unsealed -> nothing to anchor


# --- SQLite backend ---------------------------------------------------------

def test_sqlite_seal_round_trip(tmp_path, monkeypatch):
    monkeypatch.setenv(hc.LEDGER_HMAC_KEY_ENV, "s3cret")
    ledger = tmp_path / "ledger.sqlite"
    ok, _msg = hc.init_ledger(ledger)
    assert ok
    p = accept(ledger, "s1")
    conn = hc._sqlite_connect(ledger)
    row = conn.execute("SELECT value FROM claims WHERE key = ?", (MARKER,)).fetchone()
    conn.close()
    hdr = json.loads(row[0])
    assert hdr["chain_keyed"] is True and hdr["chain_seq"] >= 1
    # duplicate detection still works on the sealed sqlite ledger
    hc.complete(p, ledger)
    v = hc.check(p, registry=None, ledger_path=ledger, workspace=WS)
    assert v["decision"] == "REJECT"
    assert v["reasons"][0]["code"] == "duplicate_idempotency_key"


def test_sqlite_row_tamper_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv(hc.LEDGER_HMAC_KEY_ENV, "s3cret")
    ledger = tmp_path / "ledger.sqlite"
    p = accept(ledger, "s1")
    conn = hc._sqlite_connect(ledger)
    conn.execute("UPDATE claims SET value = '{\"state\": \"COMPLETED\"}' WHERE key = ?",
                 (p["handoff"]["idempotency_key"],))
    conn.commit()
    conn.close()
    v = hc.complete(p, ledger)
    assert v["decision"] == "REJECT"
    assert v["reasons"][0]["code"] == "ledger_corrupt"


def test_sqlite_legacy_adopt(tmp_path):
    ledger = tmp_path / "legacy.sqlite"
    conn = hc._sqlite_connect(ledger)
    conn.execute("INSERT INTO claims(key, value) VALUES (?, ?)",
                 ("old", json.dumps({"state": "COMPLETED"})))
    conn.commit()
    conn.close()
    p = accept(ledger, "s1")  # adopt on first locked acquire, no hard fail
    assert p["handoff"]["idempotency_key"] == "k-s1"


def test_sqlite_rollback_under_anchor(tmp_path, monkeypatch):
    monkeypatch.setenv(hc.LEDGER_HMAC_KEY_ENV, "s3cret")
    ledger = tmp_path / "ledger.sqlite"
    accept(ledger, "s1")
    conn = hc._sqlite_connect(ledger)
    hdr = json.loads(conn.execute("SELECT value FROM claims WHERE key = ?",
                                  (MARKER,)).fetchone()[0])
    conn.close()
    monkeypatch.setenv(hc.LEDGER_ANCHOR_ENV, f"{hdr['chain_seq'] + 5}:{hdr['chain_head']}")
    monkeypatch.setenv(hc.LEDGER_ANCHOR_REQUIRED_ENV, "1")
    v = hc.check(packet("s2"), registry=None, ledger_path=ledger, workspace=WS)
    assert v["reasons"][0]["code"] == "ledger_rollback"


def test_migrate_ledger_preserves_seal(tmp_path):
    src = tmp_path / "src.json"
    accept(src, "m1")
    dst = tmp_path / "dst.sqlite"
    report = hc.migrate_ledger(src, dst)
    assert report["entries"] == 1
    conn = hc._sqlite_connect(dst)
    row = conn.execute("SELECT value FROM claims WHERE key = ?", (MARKER,)).fetchone()
    conn.close()
    assert json.loads(row[0])["chain_head"] == header_of(src)["chain_head"]


# --- complete/release/fenced fail closed with the specific reason -----------

def test_complete_reports_rollback_reason(tmp_path, monkeypatch):
    ledger = tmp_path / "ledger.json"
    p1 = accept(ledger, "c1")
    snapshot = Path(ledger).read_bytes()
    accept(ledger, "c2")
    set_anchor_from_ledger(monkeypatch, ledger)
    Path(ledger).write_bytes(snapshot)
    out = hc.complete(p1, ledger)
    assert out["reasons"][0]["code"] == "ledger_rollback"


def test_release_reports_corrupt_reason(tmp_path):
    ledger = tmp_path / "ledger.json"
    p1 = accept(ledger, "r1")
    data = read_ledger(ledger)
    data["k-r1"]["state"] = "MANGLED"
    Path(ledger).write_text(json.dumps(data))
    out = hc.release(p1, ledger, force=True)
    assert out["reasons"][0]["code"] == "ledger_corrupt"


def test_fenced_reports_anchor_reason(tmp_path, monkeypatch):
    ledger = tmp_path / "ledger.json"
    p1 = packet("f1")
    v = hc.check(p1, registry=None, ledger_path=ledger, workspace=WS)
    assert v["decision"] == "ACCEPT"
    token = v["claim"]["token"]
    set_anchor_from_ledger(monkeypatch, ledger)
    Path(ledger).unlink()
    with pytest.raises(hc.FenceError) as exc:
        with hc.fenced(p1, ledger, token):
            pass
    assert exc.value.verdict["reasons"][0]["code"] == "ledger_rollback"
