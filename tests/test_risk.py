"""synthe_risk: one classification of a push (routine / review / high) for the approval card and the broker.

The card (synthe_approve) and the broker's risk-aware lanes (synthe_commit) read the same rules, so the
human sees the tier the broker acted on. The card's own behaviour is pinned by test_approve_card_v2.py;
these tests pin what the broker relies on: every pushed commit's paths count, the agent's words never do,
the rules are a validated operator policy, and their digest changes with them."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import synthe_approve as sa  # noqa: E402
import synthe_risk as risk  # noqa: E402

SHA = "0123456789abcdef0123456789abcdef0123beef"


def changes(files=(("M", "src/app.py"),), touched=(), stat="1 file changed, 3 insertions(+)", commits=1, **kw):
    return {"available": True, "commit": SHA, "stat": stat,
            "files": [{"status": s, "path": p} for s, p in files],
            "touched": [{"status": s, "path": p} for s, p in touched],
            "commits": [{"sha": SHA}] * commits, **kw}


def test_an_ordinary_change_is_routine():
    assert risk.assess_change(changes()) == {"tier": "routine", "reasons": [], "paths": [], "sensitive_paths": 0}


def test_the_card_and_the_broker_share_one_assessment():
    for ch in (changes(), changes(files=[("M", ".github/workflows/ci.yml")]), changes(files=[("D", "a")]),
               changes(stat="3 files changed, 250 insertions(+)"), changes(commits=risk.HIGH_COMMITS)):
        detail = {"effect": {"expected_old": "new"}, "changes": ch}
        card, broker = sa.assess(detail), risk.assess_change(ch)
        assert card == {"tier": broker["tier"], "reasons": broker["reasons"]}


def test_a_path_only_an_intermediate_commit_touches_still_counts():
    # The tip's net diff is src/ only; an earlier commit added (and a later one removed) a workflow.
    ch = changes(touched=[("A", ".github/workflows/x.yml"), ("D", ".github/workflows/x.yml"), ("M", "src/app.py")])
    out = risk.assess_change(ch)
    assert out["tier"] == "high" and out["paths"] == [".github/workflows/x.yml"]
    assert risk.assess({"changes": ch})["tier"] == "high"  # and the card shows it too


def test_renames_count_both_paths_and_deletions_count():
    out = risk.assess_change(changes(files=[("D", "ci/old.txt"), ("A", ".env.production")]))
    assert out["tier"] == "high" and ".env.production" in out["paths"]
    assert "deletes 1 file" in out["reasons"]


def test_the_full_commit_count_wins_over_a_shortened_list():
    assert risk.assess_change(changes(commits=1, commit_count=risk.HIGH_COMMITS))["tier"] == "high"


def test_updating_an_existing_branch_is_a_card_note_not_a_change_risk():
    detail = {"effect": {"expected_old": "a" * 40}, "changes": changes()}
    assert risk.assess(detail)["tier"] == "review"
    assert risk.assess_change(detail["changes"])["tier"] == "routine"


def test_missing_or_partial_evidence_is_high():
    assert risk.assess_change(None)["tier"] == "high"
    assert risk.assess_change({"available": False})["tier"] == "high"
    assert risk.assess_change(changes(patch_truncated=True))["tier"] == "high"


def test_rules_default_and_operator_lists_replace_them():
    assert risk.load_rules()["high_paths"] == list(risk.HIGH_PATHS)
    r = risk.load_rules({"high_paths": [*risk.HIGH_PATHS, "infra/*"], "review_paths": []})
    assert risk.assess_change(changes(files=[("M", "infra/main.tf")]), r)["tier"] == "high"
    assert risk.assess_change(changes(files=[("M", "package.json")]), r)["tier"] == "routine"


@pytest.mark.parametrize("conf", [{"high_paths": "*.pem"}, {"high_paths": [""]}, {"high_paths": [3]},
                                  {"thresholds": {}}, ["*.pem"], {"review_paths": ["x"] * 201}])
def test_malformed_rules_are_refused(conf):
    with pytest.raises(ValueError):
        risk.load_rules(conf)


def test_the_digest_follows_the_rules():
    d = risk.rules_digest(risk.load_rules())
    assert d == risk.rules_digest(risk.load_rules({})) == risk.rules_digest(risk.load_rules(None))
    assert d != risk.rules_digest(risk.load_rules({"review_paths": ["Makefile"]}))


def test_the_brokers_escalation_raises_the_card_never_lowers_it():
    calm = {"tier": "routine", "reasons": []}
    raised = risk.stricter(calm, {"tier": "high", "reasons": ["changes .github/workflows/x\x1b[2J.yml"]})
    assert raised["tier"] == "high" and "\x1b" not in raised["reasons"][0]
    mine = {"tier": "high", "reasons": ["deletes 12 files"]}
    assert risk.stricter(mine, {"tier": "routine", "reasons": []}) == mine
    for junk in (None, "high", {"tier": "critical"}, {}):
        assert risk.stricter(calm, junk) == calm
    detail = {"effect": {"expected_old": "new"}, "changes": changes(),
              "risk": {"tier": "high", "reasons": ["changes .env"]}}
    assert sa.assess(detail) == {"tier": "high", "reasons": ["changes .env"]}


def test_sensitive_paths_listed_are_capped_but_counted():
    many = [("M", f"deploy/k{i}.pem") for i in range(risk.MAX_RISK_PATHS + 5)]
    out = risk.assess_change(changes(files=many))
    assert len(out["paths"]) == risk.MAX_RISK_PATHS and out["sensitive_paths"] == risk.MAX_RISK_PATHS + 5
