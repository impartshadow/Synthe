#!/usr/bin/env python3
"""Two-runner simulation of the Handoff Contract GitHub Action.

WHAT THIS IS (and is not)
-------------------------
This is a LOCAL MODEL of GitHub's hosted-runner environment, built to
reproduce and then regression-test the cross-run duplicate-protection
failure that an independent reviewer found in the v0.2 Action design
(two hosted runners starting from the same empty `actions/cache` state
both ACCEPT the same packet, because `actions/cache` is immutable
snapshot storage, not an atomic compare-and-set, and the flock in the
checker only serializes processes that share one filesystem).

It is NOT a real GitHub run. It models exactly the two properties that
matter for the bug:

  * each "runner" is a separate temporary workspace with NO shared
    filesystem (separate dirs; the checker in one cannot see the
    other's ledger or lockfiles);
  * the ledger travels between runners only through an explicit,
    ordered "cache" hand-off (a directory copy standing in for
    actions/cache save/restore).

What it does NOT model: GitHub's concurrency-group queueing
latency/pending-run semantics, runner clock skew, or the real cache service
itself (the wipe in `evicted` mode stands in for the 7-day/10-GB eviction).
Those still need one real two-runner GitHub run to verify (see
OPTION2_REPORT.md).

Cache-restore semantics ARE modeled: the Action saves with key
synthe-ledger-<repo>-<run_id>-<attempt>-<phase> and restores with the bare
prefix synthe-ledger-<repo>, so on real GitHub restores always come from
restore-keys prefix fallback -- `cache-hit` is never true and the restore
signal is `cache-matched-key` (non-empty on any match, empty on a genuine
miss). The `evicted` and `prefix-restore` modes drive the real guard script
with exactly those signals.

Modes
-----
legacy   : both runners restore from the same empty snapshot and run
           concurrently-ish (no cache hand-off between them). Expected
           outcome: BOTH ACCEPT -> the v0.2 cross-run bug.
fixed    : runners are serialized (the `concurrency` group in the
           caller workflow) and runner B restores the ledger cache that
           runner A saved after its claim. Expected: A ACCEPTs, B is
           REJECTED as `duplicate` (key still RESERVED).
complete : like `fixed`, then runner A runs the complete step (flip to
           COMPLETED, save cache again), and a third presentation
           restores that. Expected: REJECT `duplicate`
           (duplicate_idempotency_key, already COMPLETED).
evicted  : runner A is the workflow's FIRST run (empty cache): the ledger
           guard passes, the claim ACCEPTs, and the ledger carries the
           chain-identity marker. The saved cache snapshot is then wiped to
           model actions/cache eviction (7 days unused / 10 GB limit), and
           runner B starts as a later run (run #2) on a fresh runner: the
           restore matches NOTHING. Expected: the guard FAILS LOUDLY
           (non-zero exit with the eviction message) BEFORE the checker
           runs -- no silent fresh start, no second ACCEPT of the same key.
prefix-restore
         : real-GitHub restore semantics: runner A is run #1 (guard passes,
           claim ACCEPTs, marker stamped). Run 2's restore matches run 1's
           full save key via PREFIX fallback (cache-hit would be false;
           cache-matched-key holds the previous save key). Two legs: (a) a
           marked ledger restores -> guard passes, chain intact; (b) a
           LEGACY ledger (marker stripped, run #42) restores -> the guard
           must WARN and continue (exit 0), never fail with a false
           EVICTED error, and the checker stamps the identity on its next
           write. Expected: all three legs hold.

Each "runner" invokes the real, unmodified checker CLI
(github-action/checker/handoff_check.py) as a subprocess, exactly as
action.yml does via run_check.sh -- the checker code and its verdict
states are untouched by the simulation. The `evicted` mode additionally
invokes the real guard script (github-action/checker/ledger_guard.sh)
exactly as action.yml does.

Usage:
  python3 simulate_two_runners.py [--mode legacy|fixed|complete|evicted|prefix-restore|all]
                                  [--keep] [--workdir DIR] [--quiet]

Exit code: 0 iff every mode's expectations hold (for `all`: legacy MUST
double-ACCEPT, fixed and complete MUST single-ACCEPT, evicted MUST fail
loudly at the guard, prefix-restore MUST keep chained runs intact and warn
(never falsely evict) on legacy ledgers). 1 otherwise.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ACTION_DIR = Path(__file__).resolve().parent
REPO_ROOT = ACTION_DIR.parent
CHECKER = ACTION_DIR / "checker" / "handoff_check.py"
GUARD = ACTION_DIR / "checker" / "ledger_guard.sh"
SRC_PACKET = REPO_ROOT / "examples" / "valid.json"
SRC_REGISTRY = REPO_ROOT / "examples" / "registry.json"
SRC_ARTIFACT = REPO_ROOT / "examples" / "artifact.txt"
LEDGER_NAME = "ledger.json"
MARKER_KEY = "~synthe"


def build_runner(base: Path, name: str) -> Path:
    """Create an isolated runner workspace: packet, registry, artifact.

    Mirrors examples/valid.json, which references the artifact by the
    relative path examples/artifact.txt, so each runner gets its own
    examples/ dir and is invoked with --workspace = runner root.
    """
    ws = base / name
    (ws / "examples").mkdir(parents=True)
    shutil.copy(SRC_PACKET, ws / "packet.json")
    shutil.copy(SRC_REGISTRY, ws / "registry.json")
    shutil.copy(SRC_ARTIFACT, ws / "examples" / "artifact.txt")
    return ws


def copy_cache(src_ws: Path, dst_ws: Path) -> bool:
    """Model actions/cache: hand the saved ledger snapshot to a runner.

    Returns True if a snapshot existed to hand over.
    """
    src = src_ws / LEDGER_NAME
    dst = dst_ws / LEDGER_NAME
    if not src.exists():
        return False
    shutil.copy(src, dst)
    return True


def run_checker(ws: Path, *extra: str) -> dict:
    """Run the real checker CLI inside a runner workspace.

    Returns {decision, state, codes, exit}.
    """
    cmd = [
        sys.executable, str(CHECKER), "packet.json",
        "--registry", "registry.json",
        "--workspace", ".",
        "--ledger", LEDGER_NAME,
        *extra,
    ]
    proc = subprocess.run(cmd, cwd=ws, capture_output=True, text=True)
    try:
        out = json.loads(proc.stdout)
    except json.JSONDecodeError:
        out = {"raw_stdout": proc.stdout, "raw_stderr": proc.stderr}
    reasons = out.get("reasons") or []
    return {
        "decision": out.get("decision"),
        "state": out.get("state") or (reasons[0].get("state") if reasons else None),
        "codes": [r.get("code") for r in reasons],
        "exit": proc.returncode,
    }


def ledger_state(ws: Path) -> str | None:
    """Return the state of the valid.json packet's key in a runner's ledger."""
    led = ws / LEDGER_NAME
    if not led.exists():
        return None
    packet = json.loads((ws / "packet.json").read_text())
    key = packet["handoff"]["idempotency_key"]
    entry = json.loads(led.read_text()).get(key)
    return (entry or {}).get("state") if entry else None


def ledger_marker(ws: Path) -> dict | None:
    """Return the chain-identity marker in a runner's ledger, if any."""
    led = ws / LEDGER_NAME
    if not led.exists():
        return None
    marker = json.loads(led.read_text()).get(MARKER_KEY)
    return marker if isinstance(marker, dict) else None


def run_guard(ws: Path, *, cache_matched_key: str | None, run_number: int,
              bootstrap: bool = False) -> dict:
    """Run the real ledger_guard.sh exactly as action.yml invokes it.

    Returns {"exit", "output"}. cache_matched_key models the restore step's
    `cache-matched-key` output: the exact key of the entry the restore
    matched (exact or restore-keys prefix fallback), or None/"" when it
    matched nothing. run_number models github.run_number.

    NOTE: on real GitHub the Action's save key is
    synthe-ledger-<repo>-<run_id>-<attempt>-<phase> while the restore uses
    the bare prefix synthe-ledger-<repo>, so real restores ALWAYS come from
    prefix fallback and cache_matched_key holds a previous run's full save
    key, never the bare primary key. Model that here: pass a full save key
    (not "") for a restored run, "" for a genuine miss.
    """
    env = dict(os.environ)
    env["LEDGER_FILE"] = str(ws / LEDGER_NAME)
    env["CACHE_MATCHED_KEY"] = cache_matched_key or ""
    env["RUN_NUMBER"] = str(run_number)
    env["LEDGER_BOOTSTRAP"] = "true" if bootstrap else "false"
    proc = subprocess.run(["bash", str(GUARD)], cwd=ws, env=env,
                          capture_output=True, text=True)
    return {"exit": proc.returncode, "output": proc.stdout + proc.stderr}


def fmt(res: dict) -> str:
    s = res["decision"] or "?"
    if res["state"]:
        s += f" [{res['state']}" + (f": {','.join(c for c in res['codes'] if c)}" if any(res["codes"]) else "") + "]"
    return s


def mode_legacy(base: Path, log) -> bool:
    """Bug reproduction: two runners, same empty snapshot, no hand-off."""
    log("\n=== MODE: legacy (v0.2 action: independent runners, same empty cache) ===")
    a = build_runner(base, "runner-a")
    b = build_runner(base, "runner-b")
    ra = run_checker(a)   # runner A claims the key
    rb = run_checker(b)   # runner B never sees A's cache save (raced runs)
    log(f"runner A: {fmt(ra)}  (ledger: {ledger_state(a)})")
    log(f"runner B: {fmt(rb)}  (ledger: {ledger_state(b)})")
    ok = ra["decision"] == "ACCEPT" and rb["decision"] == "ACCEPT"
    log("EXPECTED (the bug): both ACCEPT -> " + ("REPRODUCED" if ok else "NOT reproduced"))
    return ok


def mode_fixed(base: Path, log) -> tuple[bool, Path]:
    """Fix semantics: serialized runs, B restores A's post-claim snapshot."""
    log("\n=== MODE: fixed (concurrency group serializes runs; cache chaining) ===")
    a = build_runner(base, "runner-a")
    b = build_runner(base, "runner-b")
    ra = run_checker(a)          # claim phase: ACCEPT + RESERVED, cache saved
    handed = copy_cache(a, b)    # run B starts only after A saved (concurrency)
    rb = run_checker(b)
    log(f"runner A claim : {fmt(ra)}  (ledger: {ledger_state(a)})")
    log(f"cache hand-off A->B: {'snapshot restored' if handed else 'MISSING snapshot'}")
    log(f"runner B claim : {fmt(rb)}  (ledger: {ledger_state(b)})")
    ok = (ra["decision"] == "ACCEPT" and rb["decision"] == "REJECT"
          and rb["state"] == "duplicate")
    log("EXPECTED: exactly one ACCEPT, B REJECT duplicate -> " + ("HOLDS" if ok else "VIOLATED"))
    return ok, a


def mode_complete(base: Path, log) -> bool:
    """Completion path: claim -> effect -> complete step -> replay."""
    ok_fixed, a = mode_fixed(base / "phase1", log)
    if not ok_fixed:
        log("fixed phase failed; completion path cannot be evaluated")
        return False
    rc = run_checker(a, "--complete")   # complete step in A's workspace
    state = ledger_state(a)
    log(f"runner A complete-step: {fmt(rc)}  (ledger: {state})")
    c = build_runner(base / "phase2", "runner-c")
    handed = copy_cache(a, c)            # replay run restores post-complete cache
    rr = run_checker(c)
    log(f"cache hand-off A->C: {'snapshot restored' if handed else 'MISSING snapshot'}")
    log(f"runner C replay : {fmt(rr)}  (ledger: {ledger_state(c)})")
    ok = (rc["decision"] == "COMPLETED" and state == "COMPLETED"
          and rr["decision"] == "REJECT" and rr["state"] == "duplicate")
    log("EXPECTED: complete flips to COMPLETED; replay REJECT duplicate -> "
        + ("HOLDS" if ok else "VIOLATED"))
    return ok


REPO_SLUG = "rohansiddam/Synthe"


def save_key(run_id: int, attempt: int, phase: str) -> str:
    """The exact save key action.yml's Save step writes: per-run AND per-phase,
    because cache entries are immutable."""
    return f"synthe-ledger-{REPO_SLUG}-{run_id}-{attempt}-{phase}"


def mode_evicted(base: Path, log) -> bool:
    """Eviction must be LOUD: a restore that matches NOTHING on a non-first
    run fails the guard before the checker can silently start from an empty
    ledger."""
    log("\n=== MODE: evicted (cache evicted between runs: guard must fail loudly) ===")
    a = build_runner(base, "runner-a")
    # First workflow run: empty cache -> guard passes as a genuine first run.
    g1 = run_guard(a, cache_matched_key=None, run_number=1)
    ra = run_checker(a)
    marker = ledger_marker(a)
    marker_ok = isinstance(marker, dict) and bool(marker.get("chain_head"))
    log(f"runner A guard (first run, no matched key): exit={g1['exit']} (expect 0)")
    log(f"runner A claim: {fmt(ra)} (expect ACCEPT); chain marker stamped: {marker_ok}")
    if not (g1["exit"] == 0 and ra["decision"] == "ACCEPT" and marker_ok):
        log("first-run leg failed; eviction cannot be evaluated")
        return False
    # Model actions/cache eviction: the snapshot A saved is wiped. Runner B
    # is a fresh ephemeral runner (no ledger file) on a later workflow run,
    # so its restore matches nothing.
    b = build_runner(base, "runner-b")
    g2 = run_guard(b, cache_matched_key=None, run_number=2)
    loud = (g2["exit"] != 0 and "EVICTED" in g2["output"]
            and "REFUSES" in g2["output"])
    log(f"runner B guard (post-eviction, nothing matched, run #2): exit={g2['exit']} "
        f"(expect non-zero)")
    log(f"loud failure message (names eviction, refuses to continue): {loud}")
    # The guard runs before the checker phase in action.yml: B's checker must
    # never have run, so no ledger file may exist in B's workspace.
    no_ledger = not (b / LEDGER_NAME).exists()
    log(f"runner B ledger file exists: {not no_ledger} (expect False: checker never ran)")
    ok = loud and no_ledger
    log("EXPECTED: eviction -> loud guard failure, no silent fresh start -> "
        + ("HOLDS" if ok else "VIOLATED"))
    return ok


def mode_prefix_restore(base: Path, log) -> bool:
    """Real-GitHub restores always come from restore-keys PREFIX fallback: the
    Action saves with key synthe-ledger-<repo>-<run_id>-<attempt>-<phase> and
    restores with the bare prefix, so cache-hit is NEVER true and
    cache-matched-key holds the previous run's full save key.

    Two legs:
      (a) run 1 claims (marker stamped); run 2 restores via prefix match ->
          guard sees the marker: chain intact, proceed.
      (b) same, but the restored ledger is LEGACY (real claims, no marker --
          every current user's first run after upgrading) -> the guard must
          WARN and continue (exit 0), NOT fail with a false EVICTED error.
    """
    log("\n=== MODE: prefix-restore (real GitHub: restore via prefix fallback) ===")
    # Leg (a): chained run with the chain marker.
    a = build_runner(base, "runner-a")
    g1 = run_guard(a, cache_matched_key=None, run_number=1)
    ra = run_checker(a)
    if not (g1["exit"] == 0 and ra["decision"] == "ACCEPT"):
        log("leg (a) setup failed: run 1 did not claim")
        return False
    # Run 2: the restore matched run 1's exact save key via the prefix.
    matched = save_key(run_id=2650000001, attempt=1, phase="claim")
    b = build_runner(base, "runner-b")
    handed = copy_cache(a, b)  # snapshot handed over, as prefix restore would
    g2 = run_guard(b, cache_matched_key=matched, run_number=2)
    leg_a = handed and g2["exit"] == 0 and "chain intact" in g2["output"]
    log(f"leg (a) prefix restore, marked ledger: guard exit={g2['exit']} "
        f"(expect 0, 'chain intact') -> {'HOLDS' if leg_a else 'VIOLATED'}")
    # Leg (b): the restored ledger is legacy (claims, no marker).
    c = build_runner(base, "runner-c")
    handed_c = copy_cache(a, c)
    legacy = json.loads((c / LEDGER_NAME).read_text())
    legacy.pop(MARKER_KEY, None)  # strip the marker: pre-marker ledger
    (c / LEDGER_NAME).write_text(json.dumps(legacy))
    g3 = run_guard(c, cache_matched_key=matched, run_number=42)
    warned = "warning" in g3["output"].lower() and 'no "~synthe" chain seal' in g3["output"]
    leg_b = handed_c and g3["exit"] == 0 and warned
    log(f"leg (b) prefix restore, legacy ledger, run #42: guard exit={g3['exit']} "
        f"(expect 0 with legacy warning, NO false EVICTED) -> "
        f"{'HOLDS' if leg_b else 'VIOLATED'}")
    # After the warning the checker proceeds: a NEW key ACCEPTs and the
    # identity is stamped on that write.
    pkt_c = json.loads((c / "packet.json").read_text())
    pkt_c["handoff"]["id"] += "-runner-c"
    pkt_c["handoff"]["idempotency_key"] += "-runner-c"
    (c / "packet.json").write_text(json.dumps(pkt_c))
    rc = run_checker(c)
    marker_after = ledger_marker(c)
    stamp_ok = (rc["decision"] == "ACCEPT" and isinstance(marker_after, dict)
                and bool(marker_after.get("chain_head")))
    log(f"leg (b) checker on warned legacy ledger: {fmt(rc)}; marker stamped: {stamp_ok}")
    ok = leg_a and leg_b and stamp_ok
    log("EXPECTED: prefix restore + marked -> intact; prefix restore + legacy -> "
        "warn and continue (no false eviction); identity stamped on next write -> "
        + ("HOLDS" if ok else "VIOLATED"))
    return ok


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--mode", choices=["legacy", "fixed", "complete", "evicted",
                                       "prefix-restore", "all"],
                    default="all")
    ap.add_argument("--keep", action="store_true",
                    help="keep the simulation workspaces for inspection")
    ap.add_argument("--workdir", default=None,
                    help="base dir for workspaces (default: fresh temp dir)")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    log = (lambda *a: None) if args.quiet else print
    base = Path(args.workdir) if args.workdir else Path(
        tempfile.mkdtemp(prefix="synthe-two-runner-"))
    base.mkdir(parents=True, exist_ok=True)
    log(f"two-runner simulation (local model, not a GitHub run); workdir={base}")

    results = {}
    try:
        if args.mode in ("legacy", "all"):
            results["legacy (bug reproduced: double ACCEPT)"] = \
                mode_legacy(base / "legacy", log)
        if args.mode in ("fixed", "all"):
            ok, _ = mode_fixed(base / "fixed", log)
            results["fixed (exactly one ACCEPT)"] = ok
        if args.mode in ("complete", "all"):
            results["complete (replay of COMPLETED is duplicate)"] = \
                mode_complete(base / "complete", log)
        if args.mode in ("evicted", "all"):
            results["evicted (cache eviction fails LOUDLY at the guard)"] = \
                mode_evicted(base / "evicted", log)
        if args.mode in ("prefix-restore", "all"):
            results["prefix-restore (prefix fallback restore: marked intact, legacy warns)"] = \
                mode_prefix_restore(base / "prefix-restore", log)
    finally:
        if not args.keep and not args.workdir:
            shutil.rmtree(base, ignore_errors=True)

    log("\n--- summary ---")
    all_ok = True
    for name, ok in results.items():
        log(f"{'PASS' if ok else 'FAIL'}  {name}")
        all_ok = all_ok and ok
    if args.keep or args.workdir:
        log(f"workspaces kept at {base}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
