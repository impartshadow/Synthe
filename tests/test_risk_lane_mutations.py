"""Mutation check for risk-aware lanes: each guard removed in a copy must make tests/test_risk_lanes.py or
tests/test_risk.py fail.

Set SYNTHE_SKIP_MUTATIONS=1 to skip (each mutation runs both files in a subprocess)."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FILES = ("test_risk_lanes.py", "test_risk.py")
C, L, R = "src/synthe_commit.py", "src/synthe_lane_templates.py", "src/synthe_risk.py"

MUTATIONS = {
 "no escalation at dispatch": (C, '                        if escalation:  # before the delegate is asked, before a use is spent\n',
                               '                        if False:\n'),
 "outside paths not escalated": (C, '    if outside:\n', '    if False:\n'),
 "net diff only (broker)": (C, '                touched.append({"status": status, "path": path})\n', '                pass\n'),
 "net diff only (rules)": (R, '    every += [str(f.get("path", "")) for f in ch.get("touched") or [] if isinstance(f, dict)]\n', ''),
 "unknown tier accepted": (L, '    if "auto_approve" in x and not auto_approve_ok(x["auto_approve"]):\n        fail("template_malformed")\n', ''),
 "risk rules not in lineage": (L, '        out["risk_rules_digest"] = synthe_risk.rules_digest(risk_rules(cfg))\n', '        pass\n'),
 "escalated push re-enters the lane": (C, '    held = bool(set(ESCALATION_WAIT.values()) & set(rec.get("waiting_for") or []))\n',
                                       '    held = False\n'),
 "human approval not looked for first": (C, '        if not pending:\n', '        if not pending and (not lane or lane.get("delegate")):\n'),
 "delegate reviews a risk-escalated push": (L, '    if "risk" in held:\n', '    if False:\n'),
 "delegate reviews an out-of-lane push": (L, '    if "scope" in held:\n', '    if False:\n'),
 "staging asks the delegate anyway": (C, '        if found is not None:\n            escalated = found\n',
                                      '        if False:\n            escalated = found\n'),
 "card lowered to the broker's view": (R, '            or TIERS.index(theirs["tier"]) <= TIERS.index(mine["tier"]):', '            or True:'),
 "present use limit ignored": (L, '    return "max_uses" in t and s["uses"]', '    return False and s["uses"]'),
 "malformed use limit accepted": (L, '    if "max_uses" in x and (', '    if False and ('),
 "malformed expiry accepted": (L, '    if "expires_at" in x and (not isinstance(x["expires_at"], str) or not x["expires_at"]):\n        fail("template_malformed")\n', ''),
}


def _copy_repo(dst: Path) -> None:
    for name in ("src", "examples", "lab", "schema"):
        if not (ROOT / name).exists():
            continue
        shutil.copytree(ROOT / name, dst / name, ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"))
    (dst / "tests").mkdir()
    for name in (*FILES, "world.py", "test_speculative.py", "test_isolation.py"):
        shutil.copy2(ROOT / "tests" / name, dst / "tests" / name)


def _run(dst: Path) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider",
                           *(str(dst / "tests" / f) for f in FILES)],
                          cwd=dst, env=env, capture_output=True, text=True, timeout=600, stdin=subprocess.DEVNULL)


@pytest.mark.skipif(os.environ.get("SYNTHE_SKIP_MUTATIONS") == "1", reason="SYNTHE_SKIP_MUTATIONS=1")
def test_unmutated_copy_passes(tmp_path):
    _copy_repo(tmp_path)
    run = _run(tmp_path)
    assert run.returncode == 0, run.stdout[-2000:] + run.stderr[-2000:]


@pytest.mark.skipif(os.environ.get("SYNTHE_SKIP_MUTATIONS") == "1", reason="SYNTHE_SKIP_MUTATIONS=1")
@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_mutation_is_caught(name, tmp_path):
    rel, original, mutated = MUTATIONS[name]
    _copy_repo(tmp_path)
    target = tmp_path / rel
    text = target.read_text()
    assert text.count(original) == 1, f"mutation anchor for {name!r} not found exactly once in {rel}"
    target.write_text(text.replace(original, mutated))
    run = _run(tmp_path)
    assert run.returncode != 0, f"mutation {name!r} survived: the risk-lane tests did not notice"
