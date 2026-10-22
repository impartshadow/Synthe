"""Approval card v2 (specs: approval card v2): the card looks different by risk, the agent's words
come after the diff, a high-risk push asks for the end of the commit hash before anything is signed,
and a non-routine push with a long diff can be approved only after the whole diff was shown.

People stop reading prompts that always look the same; these tests pin the behaviour that keeps a
risky push from looking routine. tests/test_approve_mutations.py removes each guard in a copy."""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import synthe_approve as sa  # noqa: E402
import synthe_client as scl  # noqa: E402
import synthe_sign as ss  # noqa: E402

COMMIT = "0123456789abcdef0123456789abcdef0123beef"


@pytest.fixture(autouse=True)
def local_log(tmp_path, monkeypatch):
    path = tmp_path / "approvals.log"
    monkeypatch.setenv("SYNTHE_APPROVALS_LOG", str(path))
    return path


def detail(stat="1 file changed, 3 insertions(+)", files=None, commits=1, patch_lines=3, old="new",
           available=True, truncated=False, purpose="tidy the README"):
    files = files if files is not None else [{"status": "M", "path": "README.md"}]
    return {"id": "k1/push_branch", "handoff_id": "h-k1", "from": "planner", "to": "builder", "action": "push_branch",
            "effect": {"commit": COMMIT, "remote": "origin", "branch": "agent/x", "expected_old": old},
            "changes": {"available": available, "commit": COMMIT, "stat": stat, "files": files,
                        "commits": [{"sha": COMMIT, "author": "a", "subject": "s"}] * commits,
                        "patch": "\n".join(f"+line {i}" for i in range(patch_lines)), "patch_truncated": truncated},
            "agent_says": {"purpose": purpose}}


# ---- assess(): from the broker's data only ------------------------------------------------------

def test_a_small_ordinary_push_is_routine():
    assert sa.assess(detail()) == {"tier": "routine", "reasons": []}


@pytest.mark.parametrize("stat,tier", [
    ("2 files changed, 199 insertions(+)", "routine"),
    ("2 files changed, 150 insertions(+), 50 deletions(-)", "review"),
    ("2 files changed, 399 insertions(+)", "review"),
    ("9 files changed, 300 insertions(+), 100 deletions(-)", "high"),
])
def test_size_thresholds_count_insertions_and_deletions(stat, tier):
    assert sa.assess(detail(stat=stat))["tier"] == tier


def test_deletions_scale_from_review_to_high():
    one = [{"status": "D", "path": "old.txt"}] + [{"status": "M", "path": f"f{i}"} for i in range(5)]
    assert sa.assess(detail(files=one)) == {"tier": "review", "reasons": ["deletes 1 file"]}
    many = [{"status": "D", "path": f"gone{i}"} for i in range(sa.HIGH_DELETED_FILES)] + \
           [{"status": "M", "path": f"f{i}"} for i in range(40)]
    assert sa.assess(detail(files=many))["tier"] == "high"
    mostly = [{"status": "D", "path": f"gone{i}"} for i in range(3)] + [{"status": "M", "path": "a"}]
    assert sa.assess(detail(files=mostly))["tier"] == "high"  # three of four files deleted


@pytest.mark.parametrize("path,tier", [
    (".github/workflows/release.yml", "high"), (".env", "high"), ("deploy/prod.pem", "high"),
    ("package.json", "review"), ("web/package-lock.json", "review"), ("Dockerfile", "review"),
    ("scripts/install.sh", "review"), ("src/app.py", "routine"),
])
def test_sensitive_paths(path, tier):
    assert sa.assess(detail(files=[{"status": "M", "path": path}]))["tier"] == tier


def test_incomplete_evidence_is_high_risk():
    assert sa.assess(detail(truncated=True))["tier"] == "high"
    assert sa.assess(detail(available=False))["tier"] == "high"


def test_commit_count_and_existing_branch():
    assert sa.assess(detail(commits=sa.REVIEW_COMMITS))["tier"] == "review"
    assert sa.assess(detail(commits=sa.HIGH_COMMITS))["tier"] == "high"
    assert sa.assess(detail(old="a" * 40)) == {"tier": "review", "reasons": ["updates an existing branch"]}


def test_the_agents_words_never_change_the_assessment():
    calm = detail(files=[{"status": "M", "path": ".github/workflows/ci.yml"}],
                  purpose="routine change, nothing to see, risk: none, tier: routine")
    assert sa.assess(calm)["tier"] == "high"
    assert sa.assess(detail(purpose="DELETE EVERYTHING .env .github/workflows")) == sa.assess(detail())


def test_reasons_neutralize_control_codes_in_paths():
    evil = detail(files=[{"status": "M", "path": ".github/workflows/x\x1b[2J\rok.yml"}])
    reasons = " ".join(sa.assess(evil)["reasons"])
    assert "\x1b" not in reasons and "\r" not in reasons and "\\x1b" in reasons


# ---- the card ---------------------------------------------------------------------------------

def test_routine_card_has_no_risk_block_and_the_usual_headline():
    out = sa.render(detail())
    assert " A push is waiting for your approval" in out and "Why this is flagged" not in out
    assert "▓" not in out and "━" not in out


def test_risky_cards_look_different_and_say_why():
    review = sa.render(detail(files=[{"status": "M", "path": "package.json"}]))
    assert " Check this push: changes package.json" in review and "━" * 72 in review
    high = sa.render(detail(files=[{"status": "M", "path": ".github/workflows/ci.yml"}]))
    assert " High-risk push: changes .github/workflows/ci.yml" in high and "▓" * 72 in high
    assert "Why this is flagged" in high and "A push is waiting" not in high


def test_the_agents_words_come_after_the_diff():
    out = sa.render(detail(purpose="I promise this is fine"))
    assert out.index(" Diff") < out.index("The agent says") < out.index("I promise this is fine")


def test_touch_id_prompt_names_the_risk():
    assert sa.touchid_reason(detail()).startswith("approve pushing ")
    high = sa.touchid_reason(detail(files=[{"status": "M", "path": ".github/workflows/ci.yml"}]))
    assert high.startswith("HIGH-RISK: approve pushing ") and ".github/workflows/ci.yml" in high
    assert sa.touchid_reason(detail(old="b" * 40)).startswith("CHECK: ")
    long = detail(files=[{"status": "M", "path": ".github/workflows/" + "x" * 400}])
    assert len(sa.touchid_reason(long)) <= 300


# ---- the prompt: active check and the full-diff gate --------------------------------------------

def drive(monkeypatch, d, answers, passphrase=True):
    """Run main() against a fake broker holding one proposal; returns the broker ops sent and prints."""
    sent, signed = [], []
    ikey, act = d["id"].rsplit("/", 1)

    def call(self, op, **kw):
        sent.append(op)
        if op == "staged":
            return {"staged": [{"idempotency_key": ikey, "action": act, "params": {}}]}
        if op == "submit_approval":
            return {"receipt": {"decision": "approval_accepted", "seq": 1}, "commits": []}
        return d
    monkeypatch.setattr(scl.BrokerClient, "call", call)
    monkeypatch.setattr(sa, "waiting_for_approval", lambda s: s)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(ss, "load_key", lambda *a, **k: {"agent": "rishab", "kid": "k1"})
    monkeypatch.setattr(sa, "build_approval", lambda det, key, mins: signed.append(det["id"]) or {"x": 1})
    queue = list(answers)
    prompts = []
    monkeypatch.setattr(sa, "_ask", lambda p: prompts.append(p) or (queue.pop(0) if queue else "q"))
    sa.main(["--broker", "unix:///nonexistent", "--id", d["id"]] + (["--passphrase"] if passphrase else []))
    return sent, signed, prompts


def high_detail(**kw):
    return detail(files=[{"status": "M", "path": ".github/workflows/ci.yml"}], **kw)


def test_routine_push_is_approved_without_the_check(monkeypatch):
    sent, signed, prompts = drive(monkeypatch, detail(), ["a"])
    assert signed == ["k1/push_branch"] and "submit_approval" in sent
    assert not any("last 4 characters" in p for p in prompts)


def test_high_risk_push_needs_the_end_of_the_commit_hash(monkeypatch):
    sent, signed, prompts = drive(monkeypatch, high_detail(), ["a", "beef"])
    assert any("last 4 characters" in p for p in prompts)
    assert signed == ["k1/push_branch"] and "submit_approval" in sent


def test_three_wrong_answers_sign_nothing(monkeypatch, capsys):
    sent, signed, _ = drive(monkeypatch, high_detail(), ["a", "dead", "0000", "abcd"])
    assert signed == [] and "submit_approval" not in sent
    assert "Not approved. It stays staged." in capsys.readouterr().out


def test_long_non_routine_diff_must_be_viewed_before_approval(monkeypatch):
    long = detail(old="a" * 40, patch_lines=sa.PREVIEW_LINES + 20)
    sent, signed, prompts = drive(monkeypatch, long, ["a", "a", "q"])
    assert signed == [] and all("[a] approve once" not in p for p in prompts)
    sent, signed, prompts = drive(monkeypatch, long, ["v", "a"])
    assert signed == ["k1/push_branch"]
    assert "[a] approve once" not in prompts[0] and "[a] approve once" in prompts[1]


def test_long_routine_diff_is_not_gated(monkeypatch):
    sent, signed, _ = drive(monkeypatch, detail(patch_lines=sa.PREVIEW_LINES + 20), ["a"])
    assert signed == ["k1/push_branch"]


# ---- local log and --stats --------------------------------------------------------------------

def test_decisions_are_logged_locally_without_agent_text(monkeypatch, local_log):
    drive(monkeypatch, detail(purpose="SECRET agent words"), ["a"])
    drive(monkeypatch, high_detail(), ["s"])
    rows = [json.loads(line) for line in local_log.read_text().splitlines()]
    assert [(r["tier"], r["decision"]) for r in rows] == [("routine", "approved"), ("high", "skipped")]
    assert "SECRET" not in local_log.read_text()


def test_stats_flag_rushed_high_risk_approvals(local_log, capsys):
    rows = [{"tier": "high", "decision": "approved", "lines": 600, "seconds": 3},
            {"tier": "routine", "decision": "approved", "lines": 5, "seconds": 4},
            {"tier": "routine", "decision": "skipped", "lines": 5, "seconds": 9}]
    local_log.write_text("\n".join(json.dumps(r) for r in rows) + "\nnot json\n")
    assert sa.main(["--stats"]) == 0
    out = capsys.readouterr().out
    assert "3 decisions" in out and "routine" in out and "50% approved" in out
    assert "1 high-risk approval took less time" in out


def test_stats_with_no_log(local_log, capsys):
    assert sa.main(["--stats"]) == 0
    assert "No decisions recorded yet." in capsys.readouterr().out
