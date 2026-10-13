"""Ledger durability (build-queue item 9): cache eviction must be LOUD.

Two layers:
  1. src/handoff_check.py stamps every ledger with a chain-identity marker
     ("~synthe") so "first run" is distinguishable from "cache evicted".
  2. github-action/checker/ledger_guard.sh -- run by action.yml after the
     actions/cache restore and before the checker phase -- fails the run
     loudly when the restore misses but a ledger chain was expected, instead
     of letting the checker silently start from an empty ledger (which would
     downgrade exactly-once duplicate protection to at-most-once).
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import handoff_check as hc  # noqa: E402

GUARD = ROOT / "github-action" / "checker" / "ledger_guard.sh"
V3 = ROOT / "examples" / "v03"
MARKER = hc.LEDGER_META_KEY  # the ledger-integrity chain seal doubles as the chain marker


def claim(ledger):
    packet = json.loads((V3 / "packets" / "valid-signed.json").read_text())
    reg = json.loads((V3 / "registry.json").read_text())
    verdict = hc.check(packet, registry=reg, ledger_path=ledger,
                       workspace=V3 / "workspace")
    assert verdict["decision"] == "ACCEPT", verdict
    return packet, reg, verdict


def claim_unsigned(ledger, key_suffix=""):
    """Claim with the unsigned examples/valid.json packet (mutable key)."""
    packet = json.loads((ROOT / "examples" / "valid.json").read_text())
    if key_suffix:
        packet["handoff"]["idempotency_key"] += key_suffix
        packet["handoff"]["id"] += key_suffix
    reg = json.loads((ROOT / "examples" / "registry.json").read_text())
    ws = tmp_examples_workspace()
    verdict = hc.check(packet, registry=reg, ledger_path=ledger, workspace=ws)
    assert verdict["decision"] == "ACCEPT", verdict
    return packet


def tmp_examples_workspace():
    """examples/valid.json references examples/artifact.txt relatively."""
    ws = Path(tempfile.mkdtemp(prefix="synthe-ws-"))
    (ws / "examples").mkdir()
    shutil.copy(ROOT / "examples" / "artifact.txt", ws / "examples" / "artifact.txt")
    return ws


def read_marker(ledger_path):
    data = json.loads(Path(ledger_path).read_text())
    marker = data.get(MARKER)
    assert isinstance(marker, dict), f"no chain marker in {ledger_path}"
    return marker


# --- Layer 1: the chain-identity marker ------------------------------------

def test_first_claim_stamps_chain_marker(tmp_path):
    ledger = tmp_path / "ledger.json"
    claim(ledger)
    marker = read_marker(ledger)
    assert marker["chain_format"] == hc.LEDGER_CHAIN_FORMAT
    assert marker["chain_seq"] >= 1
    assert isinstance(marker["chain_head"], str) and marker["chain_head"]


def test_marker_preserved_across_chained_runs(tmp_path):
    """A run that restores the previous ledger extends its chain; it never
    starts a new one."""
    ledger = tmp_path / "ledger.json"
    claim_unsigned(ledger)
    first = read_marker(ledger)
    claim_unsigned(ledger, key_suffix="-second")
    marker = read_marker(ledger)
    assert marker["chain_seq"] > first["chain_seq"]
    assert marker["chain_prev"] == first["chain_head"]


def test_marker_survives_complete_and_terminal_replay(tmp_path):
    ledger = tmp_path / "ledger.json"
    packet, _, _ = claim(ledger)
    first_seq = read_marker(ledger)["chain_seq"]
    out = hc.complete(packet, ledger)
    assert out["decision"] == "COMPLETED", out
    assert read_marker(ledger)["chain_seq"] > first_seq
    # Replay of the COMPLETED key is still a terminal duplicate.
    reg = json.loads((V3 / "registry.json").read_text())
    replay = hc.check(packet, registry=reg, ledger_path=ledger,
                      workspace=V3 / "workspace")
    assert replay["decision"] == "REJECT"
    assert replay["reasons"][0]["code"] == "duplicate_idempotency_key"


def test_legacy_ledger_gets_fresh_marker_on_next_write(tmp_path):
    """A pre-marker ledger (claims, no seal) is sealed on its next write."""
    ledger = tmp_path / "ledger.json"
    ledger.write_text(json.dumps({"old-key": {"state": "COMPLETED"}}))
    claim(ledger)
    assert read_marker(ledger)["chain_head"]
    assert json.loads(ledger.read_text())["old-key"]["state"] == "COMPLETED"


def test_marker_migrates_to_sqlite(tmp_path):
    src = tmp_path / "ledger.json"
    claim(src)
    dst = tmp_path / "ledger.sqlite"
    hc.migrate_ledger(src, dst)
    with hc.LockedLedger(dst) as locked:
        marker = locked.ledger.get(MARKER)
    assert isinstance(marker, dict) and marker.get("chain_head")


def test_marker_ignored_by_wait_for_and_path_scans():
    """The marker must not trip the cross-key scans or create false conflicts."""
    marker = hc.seal_ledger({})[MARKER]
    ledger = {MARKER: marker,
              "key-a": {"state": "RESERVED", "to": "bob",
                        "owned_paths": ["src/**"]}}
    # Dependency scan: marker is not a live claim, never part of a cycle.
    assert hc._dependency_cycle(ledger, "key-b", [MARKER]) is None
    # Path scan: no overlap -> no conflicts; the marker contributes nothing.
    h = {"scope": {"owned_paths": ["unrelated/**"]}, "to": "bob"}
    assert hc._path_conflicts(ledger, h, "key-b") == []
    # ... and a real overlap is still detected with the marker present.
    h2 = {"scope": {"owned_paths": ["src/main.py"]}, "to": "bob"}
    conflicts = hc._path_conflicts(ledger, h2, "key-b")
    assert [c[0] for c in conflicts] == ["key-a"]
    # A packet that (perversely) used the reserved key can never claim it:
    # the marker reads as an already-COMPLETED entry -> terminal duplicate.
    assert hc.entry_state(marker) == "COMPLETED"


def test_corrupt_ledger_is_not_stamped(tmp_path):
    ledger = tmp_path / "ledger.json"
    ledger.write_text("{not json")
    with hc.LockedLedger(ledger) as locked:
        assert locked.ledger.get("_corrupt") is True
        assert MARKER not in locked.ledger


# --- Layer 2: the eviction guard --------------------------------------------
#
# The restore signal is steps.restore.outputs.cache-matched-key, NOT
# cache-hit. The Action saves with a per-run/per-phase key
# (synthe-ledger-<repo>-<run_id>-<attempt>-<phase>) and restores with the bare
# prefix, so on real GitHub every restore comes from restore-keys PREFIX
# fallback: cache-hit is never true, and cache-matched-key holds the previous
# run's full save key (non-empty) or "" on a genuine miss.

# A realistic previous-run save key, as cache-matched-key would report it on
# a prefix-fallback restore on real GitHub.
PREV_SAVE_KEY = "synthe-ledger-rohansiddam/Synthe-2650000001-1-claim"


def run_guard(tmp_path, *, cache_matched_key=None, run_number,
              bootstrap=False, ledger_text=None):
    ws = tmp_path / "ws"
    ws.mkdir()
    ledger_file = ws / "ledger.json"
    if ledger_text is not None:
        ledger_file.write_text(ledger_text)
    env = dict(os.environ)
    env["LEDGER_FILE"] = str(ledger_file)
    env["CACHE_MATCHED_KEY"] = cache_matched_key or ""
    env["RUN_NUMBER"] = str(run_number)
    env["LEDGER_BOOTSTRAP"] = "true" if bootstrap else "false"
    proc = subprocess.run(["bash", str(GUARD)], cwd=ws, env=env,
                          capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def marked_ledger_text():
    return json.dumps(hc.seal_ledger({}))


def legacy_ledger_text():
    return json.dumps({"k": {"state": "COMPLETED"}})  # claims, no marker


def test_guard_first_run_passes(tmp_path):
    """Genuine first run: restore matches nothing on run #1 -> fresh chain."""
    code, out = run_guard(tmp_path, cache_matched_key=None, run_number=1)
    assert code == 0, out
    assert "first workflow run" in out


def test_guard_eviction_fails_loudly(tmp_path):
    """Genuine eviction: restore matches nothing on a later run, no ledger
    file -> loud failure."""
    code, out = run_guard(tmp_path, cache_matched_key=None, run_number=7)
    assert code != 0, out
    assert "EVICTED" in out
    assert "REFUSES" in out
    assert "ledger-bootstrap" in out  # recovery path is named


def test_guard_bootstrap_declares_fresh_chain(tmp_path):
    """Operator-declared recovery: one bootstrap run skips the guard."""
    code, out = run_guard(tmp_path, cache_matched_key=None, run_number=7,
                          bootstrap=True)
    assert code == 0, out
    assert "fresh ledger chain" in out


def test_guard_prefix_restore_with_marker_passes(tmp_path):
    """The real-GitHub case: the restore matched a previous run's save key
    via prefix fallback (a full save key, NOT the bare primary key) and the
    ledger carries its marker -> chain intact."""
    assert PREV_SAVE_KEY.startswith("synthe-ledger-")  # sanity: it is a
    assert PREV_SAVE_KEY != "synthe-ledger-rohansiddam/Synthe"  # prefix key,
    # not the exact primary key (which never matches a real save)
    code, out = run_guard(tmp_path, cache_matched_key=PREV_SAVE_KEY,
                          run_number=7, ledger_text=marked_ledger_text())
    assert code == 0, out
    assert "chain intact" in out


def test_guard_prefix_restore_legacy_ledger_warns_but_passes(tmp_path):
    """The reviewer's repro: a legacy ledger (real claims, NO marker) restored
    via prefix fallback on run 42 -> WARN and continue, never a false
    EVICTED failure. (v1 read this as a miss because cache-hit is never true
    on real GitHub.)"""
    code, out = run_guard(tmp_path, cache_matched_key=PREV_SAVE_KEY,
                          run_number=42, ledger_text=legacy_ledger_text())
    assert code == 0, out
    assert "EVICTED" not in out
    assert 'no "~synthe" chain seal' in out


def test_guard_prefix_restore_missing_file_warns_but_passes(tmp_path):
    """Restore matched a key but no ledger file materialized: anomalous, but
    not an eviction -> warn and continue."""
    code, out = run_guard(tmp_path, cache_matched_key=PREV_SAVE_KEY,
                          run_number=7)
    assert code == 0, out
    assert "EVICTED" not in out


def test_guard_miss_but_marker_file_present_passes(tmp_path):
    """File already present in this job despite the miss: proceed."""
    code, out = run_guard(tmp_path, cache_matched_key=None, run_number=7,
                          ledger_text=marked_ledger_text())
    assert code == 0, out


def test_guard_miss_with_unmarked_file_present_passes(tmp_path):
    """A ledger file exists but the restore matched nothing (e.g. created
    earlier in this job): there is a chain to continue, so proceed."""
    code, out = run_guard(tmp_path, cache_matched_key=None, run_number=7,
                          ledger_text=legacy_ledger_text())
    assert code == 0, out
    assert "EVICTED" not in out


# --- Layer 3: the reserved "~" namespace is enforced, not just documented ---

def test_reserved_tilde_prefix_rejected_in_validate(tmp_path):
    """A packet whose idempotency_key starts with '~' is invalid: the '~'
    prefix is the reserved chain-identity namespace ('~synthe'), shared with
    the ledger-integrity item. No sender may claim a key inside it."""
    packet = json.loads((ROOT / "examples" / "valid.json").read_text())
    packet["handoff"]["idempotency_key"] = "~synthe-spoof"
    reg = json.loads((ROOT / "examples" / "registry.json").read_text())
    ws = tmp_examples_workspace()
    verdict = hc.check(packet, registry=reg,
                       ledger_path=tmp_path / "ledger.json", workspace=ws)
    assert verdict["decision"] == "REJECT", verdict
    codes = [r["code"] for r in verdict.get("reasons", [])]
    assert "reserved_idempotency_key" in codes, codes


def test_reserved_tilde_prefix_rejected_even_without_marker(tmp_path):
    """The check fires in validate() itself, so it holds for every ledger
    shape -- including a ledger that already carries the real marker."""
    ledger = tmp_path / "ledger.json"
    claim_unsigned(ledger)  # stamps the real marker
    packet = json.loads((ROOT / "examples" / "valid.json").read_text())
    packet["handoff"]["idempotency_key"] = "~anything"
    packet["handoff"]["id"] += "-tilde"
    reg = json.loads((ROOT / "examples" / "registry.json").read_text())
    ws = tmp_examples_workspace()
    verdict = hc.check(packet, registry=reg, ledger_path=ledger,
                       workspace=ws)
    assert verdict["decision"] == "REJECT", verdict
    codes = [r["code"] for r in verdict.get("reasons", [])]
    assert "reserved_idempotency_key" in codes, codes


# --- Full simulated path: eviction between runs ------------------------------

SPEC = importlib.util.spec_from_file_location(
    "simulate_two_runners",
    ROOT / "github-action" / "simulate_two_runners.py")
SIM = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SIM)


def test_S4_evicted_shape_guard_fails_loudly(tmp_path):
    """Simulated cache eviction (ledger wiped between runs): the guard fails
    loudly instead of the run silently starting from an empty ledger;
    genuine first runs still ACCEPT."""
    assert SIM.mode_evicted(tmp_path, lambda *a: None)


def test_S5_prefix_restore_shape_legacy_warns_not_evicted(tmp_path):
    """Real-GitHub restore semantics (prefix fallback, cache-hit never true):
    chained runs stay intact, and a restored legacy ledger (no marker) warns
    and continues -- never a false EVICTED failure."""
    assert SIM.mode_prefix_restore(tmp_path, lambda *a: None)
