"""Risk-aware lanes: inside a grant, routine pushes go out with no human; anything riskier waits for one.

A grant that carries `"auto_approve": [...]` (signed with the rest of it) approves only those tiers. The
broker classifies what it is about to push (synthe_risk, on its own copy of every pushed commit, under the
lane lock immediately before dispatch). Any other tier stays STAGED for a human's normal approval, with a
`risk_escalated` reason and a `risk` record (paths, never contents); the delegate is not asked and no use
is spent. Grants without the field behave as before.

Likewise, under any grant, a push that touches paths outside the grant's `path_scope` is not the grant's to
approve: it waits for a human (`outside_lane_paths`, a `lane_scope` record), like any push without a lane.
Paths the receiver policy refuses (allowed_paths, forbidden_paths, owned_paths) are still denied outright,
whoever approves.

tests/test_risk_lane_mutations.py removes each guard in a copy and checks this file (or test_risk.py) fails.
"""
import datetime as dt
import json

import pytest

from test_speculative import PUSH, detached, speculative_claim
from world import World, cm, mkkey, ts, codes
import synthe_approve as sa
import synthe_lane_templates as lanes
import synthe_risk

DELEGATE = "claude-reviewer"
WORKFLOW = ".github/workflows/ci.yml"
SECRET_TEXT = "do-not-leak-this-workflow-body"


@pytest.fixture
def w(tmp_path):
    w = World(tmp_path, policy={
        "allowed_paths": ["src/**", "tests/**", "docs/**", ".github/**", "package.json"],
        "defaults": {"owned_paths": ["src/**", "tests/**", ".github/**", "package.json"],
                     "output_schema": "code_change.v1", "budget": {"tokens": 100000, "usd": 5, "minutes": 60}}})
    w.cfg.raw["lane_templates"] = {"receivers": ["builder"]}
    w.keys[DELEGATE], pub = mkkey(DELEGATE)
    w.registry["agents"][DELEGATE] = {"role": "reviewer", "kind": "model_approver", "keys": [pub]}
    w.save_registry()
    return w


def grant(w, auto_approve=("routine",), delegate=None, **updates):
    x = {"template_id": "lane-1", "receiver": "builder", "tool": "git_push",
         "params": {"remote": "origin", "branch_pattern": "feature/*"},
         "path_scope": ["src/**", "tests/**", ".github/**", "package.json"], "max_uses": 3,
         "expires_at": ts(dt.timedelta(days=1)),
         "lineage": lanes.lineage(w.cfg, w.registry, "builder", risk_aware=auto_approve is not None)}
    if auto_approve is not None:
        x["auto_approve"] = list(auto_approve)
    if delegate:
        x["delegate"] = delegate
    x.update(updates)
    return lanes.sign(x, w.keys["rishab"])


def claim(w, key="k1", branch="feature/x", **kw):
    p = w.packet(idem=key, branch=branch, approve=False, **kw)
    return p, speculative_claim(w, p)


def push(w, files, key="k1", branch="feature/x", delete=(), wait=False):
    p, tok = claim(w, key, branch)
    sha = w.commit(files, msg=key, delete=delete)
    return p, tok, sha, w.propose(p, tok, sha, branch=branch, **({"wait_for_approval": True} if wait else {}))


def uses_left(w):
    return lanes.view(w.cfg)["templates"][0]["uses_left"]


def human(w, p, sha, branch="feature/x"):
    return cm.submit_approval(w.cfg, detached(w, p, params={"remote": "origin", "branch": branch, "commit": sha}))


def staged(w, key="k1"):
    return cm.staged_view(w.cfg, key)[0]


# ---- (a) routine goes out alone; (b) risky stays staged; (c) a human then ships it --------------------

def test_a_routine_push_executes_with_no_human(w):
    lanes.submit(w.cfg, grant(w))
    *_, sha, r = push(w, {"src/app.py": "print('v2')\n"})
    assert r["decision"] == "executed", r
    assert w.remote_ref("feature/x") == sha and r["lane_template"]["use"] == 1 and uses_left(w) == 2
    assert (r["risk"]["tier"], r["risk"]["escalated"], r["risk"]["auto_approve"]) == ("routine", False, ["routine"])
    assert r["approvals"] == []  # nobody but the grant
    assert w.chain()["ok"]


def test_a_workflow_change_escalates_stays_staged_and_spends_no_use(w):
    lanes.submit(w.cfg, grant(w))
    *_, sha, r = push(w, {WORKFLOW: f"on: push # {SECRET_TEXT}\n", "src/app.py": "print('v2')\n"})
    assert r["decision"] == "staged", r
    assert {"risk_escalated", "staged"} <= codes(r) and codes(r) & cm.APPROVAL_CODES
    risk = r["risk"]
    assert (risk["tier"], risk["escalated"], risk["template_id"], risk["commit"]) == ("high", True, "lane-1", sha)
    assert risk["paths"] == [WORKFLOW] and risk["reasons"][0] == f"changes {WORKFLOW}"
    assert risk["rules_digest"] == synthe_risk.rules_digest(synthe_risk.load_rules())
    msg = [x["message"] for x in r["reasons"] if x["code"] == "risk_escalated"][0]
    assert "needs a human" in msg and WORKFLOW in msg
    assert w.remote_ref("feature/x") is None and uses_left(w) == 3
    assert staged(w)["waiting_for"] == ["approval", "risk"] and staged(w)["risk"]["tier"] == "high"
    assert "lane_template" not in r
    # paths only: the file's contents never reach the evidence chain
    assert SECRET_TEXT not in w.cfg.receipts_path.read_text()
    # the sweeper leaves it for the human: no re-dispatch, no new receipt, no use
    n = len(w.chain()["receipts"])
    assert cm.retry_staged(w.cfg, sweep=True) == [] and len(w.chain()["receipts"]) == n and uses_left(w) == 3


def test_the_human_sees_the_tier_the_broker_acted_on_then_approves_it_normally(w):
    lanes.submit(w.cfg, grant(w))
    p, _, sha, r = push(w, {WORKFLOW: "on: push\n"})
    detail = cm.staged_detail(w.cfg, f"k1/{PUSH}")
    assert detail["risk"]["tier"] == "high" and sa.assess(detail)["tier"] == "high"
    assert [x for x in sa.waiting_for_approval(cm.staged_view(w.cfg))] and sa.headline(sa.assess(detail)).startswith(" High-risk")
    out = human(w, p, sha)
    [c] = out["commits"]
    assert c["decision"] == "executed", c
    assert w.remote_ref("feature/x") == sha
    assert c["approvals"][0]["approver"] == "rishab" and "lane_template" not in c and uses_left(w) == 3
    assert c["triggered_by"]["kind"] == "approval" and w.chain()["ok"]


# ---- (d) every pushed commit, not the tip ----------------------------------------------------------

def test_an_intermediate_commit_touching_a_workflow_escalates_though_the_tip_does_not(w):
    lanes.submit(w.cfg, grant(w))
    p, tok = claim(w)
    w.commit({WORKFLOW: "on: push\n"}, msg="add a workflow")
    sha = w.commit({"src/app.py": "print('v2')\n"}, msg="remove it again", delete=(WORKFLOW,))
    r = w.propose(p, tok, sha)
    assert r["decision"] == "staged" and "risk_escalated" in codes(r), r
    assert r["risk"]["paths"] == [WORKFLOW] and WORKFLOW not in json.dumps(cm.staged_detail(w.cfg, f"k1/{PUSH}")
                                                                             ["changes"]["files"])
    assert w.remote_ref("feature/x") is None and uses_left(w) == 3


# ---- (e) classified again at dispatch ------------------------------------------------------------

def test_a_restaged_routine_commit_is_classified_anew_and_goes_out(w):
    lanes.submit(w.cfg, grant(w))
    p, tok = claim(w)
    risky = w.commit({WORKFLOW: "on: push\n"}, msg="risky")
    assert w.propose(p, tok, risky)["decision"] == "staged"
    w.commit({"src/app.py": "print('v3')\n"}, msg="calm", delete=(WORKFLOW,))
    from world import git
    git(w.agent, "reset", "-q", "--soft", "HEAD~2")
    calm = w.commit({"src/app.py": "print('v3')\n"}, msg="calm only")
    r = w.propose(p, tok, calm)
    assert r["decision"] == "executed" and r["risk"]["tier"] == "routine", r
    assert w.remote_ref("feature/x") == calm and staged(w)["state"] == "SUPERSEDED"


def test_a_stale_classification_never_ships_a_restaged_risky_commit(w, monkeypatch):
    # A downstream waits on its upstream. While it waits, it is restaged with a workflow change, and the
    # classification made at staging is (here, deliberately) stale. Dispatch classifies the exact range
    # being pushed again, under the lane lock, so it still goes to a human.
    lanes.submit(w.cfg, grant(w))
    up = w.packet(idem="up", branch="feature/up")
    up_tok = w.claim(up)
    down, down_tok = claim(w, "down", "feature/down", depends_on=["up"])
    a = w.commit({"src/app.py": "print('down')\n"}, msg="down")
    r = w.propose(down, down_tok, a, branch="feature/down", wait_for_approval=True)
    assert r["decision"] == "staged" and r["staged"]["waiting_for"] == ["dependency"], r
    real = cm._lane_risk
    monkeypatch.setattr(cm, "_lane_risk", lambda *x: {**real(*x), "tier": "routine", "escalated": False})
    b = w.commit({WORKFLOW: "on: push\n"}, msg="down, now with a workflow")
    r = w.propose(down, down_tok, b, branch="feature/down", wait_for_approval=True)
    assert r["decision"] == "staged" and staged(w, "down")["waiting_for"] == ["dependency"]
    monkeypatch.setattr(cm, "_lane_risk", real)
    done = w.propose(up, up_tok, w.commit({"src/app.py": "print('up')\n"}, msg="up"), branch="feature/up")
    assert done["decision"] == "executed"
    assert w.remote_ref("feature/down") is None
    assert staged(w, "down")["waiting_for"] == ["approval", "risk"] and staged(w, "down")["risk"]["commit"] == b
    assert uses_left(w) == 3  # neither the escalated downstream nor the human-approved upstream spent one


def test_the_classification_at_staging_also_names_who_is_asked(w):
    lanes.submit(w.cfg, grant(w))
    _, _, _, r = push(w, {WORKFLOW: "on: push\n"}, wait=True)
    assert r["decision"] == "staged" and r["staged"]["waiting_for"] == ["approval", "risk"]


# ---- grants with a delegate ------------------------------------------------------------------------

def delegate_doc(w, sha, key="k1", branch="feature/x"):
    return lanes.sign_delegate({"template_id": "lane-1", "idempotency_key": key, "from": "planner", "to": "builder",
                                "action": PUSH, "params": {"remote": "origin", "branch": branch, "commit": sha},
                                "note": "fine", "expires_at": ts(dt.timedelta(minutes=30))}, w.keys[DELEGATE])


def test_with_a_delegate_high_risk_goes_to_a_human_and_the_delegate_is_not_asked(w):
    lanes.submit(w.cfg, grant(w, auto_approve=lanes.DEFAULT_AUTO_APPROVE, delegate=DELEGATE))
    p, _, sha, r = push(w, {WORKFLOW: "on: push\n"}, wait=True)
    assert r["decision"] == "staged" and staged(w)["waiting_for"] == ["approval", "risk"], r
    assert "delegate_approval_missing" not in codes(r)
    out = cm.submit_delegate(w.cfg, delegate_doc(w, sha))
    assert out["receipt"]["decision"] == "delegate_approval_rejected" and "risk_escalated" in codes(out["receipt"])
    assert w.remote_ref("feature/x") is None
    assert [c["decision"] for c in human(w, p, sha)["commits"]] == ["executed"] and uses_left(w) == 3


def test_with_a_delegate_a_review_tier_push_is_the_delegates_to_approve(w):
    lanes.submit(w.cfg, grant(w, auto_approve=lanes.DEFAULT_AUTO_APPROVE, delegate=DELEGATE))
    *_, sha, r = push(w, {"package.json": "{}\n"}, wait=True)
    assert r["decision"] == "staged" and staged(w)["waiting_for"] == ["approval", "review"], r
    [c] = cm.submit_delegate(w.cfg, delegate_doc(w, sha))["commits"]
    assert c["decision"] == "executed" and c["risk"]["tier"] == "review" and c["approvals"][0]["delegate"] is True
    assert uses_left(w) == 2


def test_a_delegate_approval_never_carries_a_push_dispatch_classifies_as_too_risky(w, monkeypatch):
    lanes.submit(w.cfg, grant(w, auto_approve=["routine"], delegate=DELEGATE))
    real = cm._lane_risk
    monkeypatch.setattr(cm, "_lane_risk", lambda *x: {**real(*x), "tier": "routine", "escalated": False})
    *_, sha, r = push(w, {WORKFLOW: "on: push\n"}, wait=True)
    assert staged(w)["waiting_for"] == ["approval", "review"]  # a (stale) routine classification asked the delegate
    monkeypatch.setattr(cm, "_lane_risk", real)
    [c] = cm.submit_delegate(w.cfg, delegate_doc(w, sha))["commits"]
    assert c["decision"] == "staged" and "risk_escalated" in codes(c), c
    assert w.remote_ref("feature/x") is None and uses_left(w) == 3 and staged(w)["waiting_for"] == ["approval", "risk"]


# ---- what the grant says, and who may say it --------------------------------------------------------

@pytest.mark.parametrize("tiers,ships", [(["routine"], False), (["routine", "review"], True)])
def test_the_grant_decides_which_tiers_ship(w, tiers, ships):
    lanes.submit(w.cfg, grant(w, auto_approve=tiers))
    *_, sha, r = push(w, {"package.json": "{}\n"})
    assert r["risk"]["tier"] == "review"
    assert (r["decision"] == "executed") is ships and (w.remote_ref("feature/x") == sha) is ships


def test_a_second_push_to_the_same_branch_stays_routine(w):
    lanes.submit(w.cfg, grant(w))
    assert push(w, {"src/app.py": "print('one')\n"})[3]["decision"] == "executed"
    *_, sha, r = push(w, {"src/app.py": "print('two')\n"}, key="k2")
    assert r["decision"] == "executed" and r["risk"]["tier"] == "routine" and w.remote_ref("feature/x") == sha


def test_deleting_a_file_needs_a_human_under_a_routine_only_grant(w):
    lanes.submit(w.cfg, grant(w, auto_approve=["routine"]))
    *_, r = push(w, {"src/other.py": "x\n"}, delete=("src/app.py",))
    assert r["decision"] == "staged" and r["risk"]["tier"] == "review" and "deletes 1 file" in r["risk"]["reasons"]


@pytest.mark.parametrize("tiers", [["routine", "critical"], [], "routine", ["routine", "routine"], [None], ["HIGH"]])
def test_a_grant_with_an_unknown_or_malformed_tier_is_refused(w, tiers):
    body = {k: v for k, v in grant(w).items() if k not in ("approver", "kid", "sig")}
    body["auto_approve"] = tiers  # signed by the human, lineage right: only the tiers are wrong
    with pytest.raises(cm.Deny, match="template malformed"):
        lanes.submit(w.cfg, lanes.sign(body, w.keys["rishab"]))
    assert lanes.view(w.cfg)["templates"] == []


def test_an_old_grant_without_the_field_behaves_as_before(w):
    lanes.submit(w.cfg, grant(w, auto_approve=None))
    *_, sha, r = push(w, {WORKFLOW: "on: push\n"})
    assert r["decision"] == "executed" and w.remote_ref("feature/x") == sha and "risk" not in r
    assert r["lane_template"]["use"] == 1


def test_the_field_is_signed(w):
    x = grant(w)
    x["auto_approve"] = ["routine", "review", "high"]
    with pytest.raises(cm.Deny, match="signature invalid"):
        lanes.submit(w.cfg, x)
    y = grant(w)
    del y["auto_approve"]  # dropping it would make the grant approve every tier
    with pytest.raises(cm.Deny, match="signature invalid"):
        lanes.submit(w.cfg, y)


def test_changing_the_risk_rules_makes_risk_aware_grants_stale(w, monkeypatch):
    lanes.submit(w.cfg, grant(w))
    legacy = grant(w, auto_approve=None, template_id="lane-old")
    lanes.submit(w.cfg, legacy)
    monkeypatch.setattr(synthe_risk, "HIGH_PATHS", synthe_risk.HIGH_PATHS[1:])  # a release changes the defaults
    status = {t["template_id"]: t["status"] for t in lanes.view(w.cfg)["templates"]}
    assert status == {"lane-1": "template_stale", "lane-old": "active"}


def test_operator_risk_paths_apply_and_are_validated(w):
    w.cfg.effects["git_push"]["risk"] = {"high_paths": [*synthe_risk.HIGH_PATHS, "src/deploy/*"]}
    lanes.submit(w.cfg, grant(w))
    *_, r = push(w, {"src/deploy/prod.py": "x\n"})
    assert r["decision"] == "staged" and r["risk"]["paths"] == ["src/deploy/prod.py"]
    w.cfg.effects["git_push"]["risk"] = {"high_paths": "src/deploy/*"}  # malformed: no grant applies, a human must
    assert lanes.view(w.cfg)["templates"][0]["status"] == "risk_rules_invalid"
    *_, r = push(w, {"src/app.py": "y\n"}, key="k2", branch="feature/y")
    assert r["decision"] == "denied" and codes(r) & cm.APPROVAL_CODES


def test_the_draft_op_hands_out_the_matching_lineage(w):
    import synthe_broker as sb
    b = sb.Broker.__new__(sb.Broker)
    b.cfg = w.cfg
    out = b.op_lane_template_draft({"receiver": "builder", "auto_approve": ["routine"]}, None)
    assert out["lineage"] == lanes.lineage(w.cfg, w.registry, "builder", risk_aware=True)
    assert out["auto_approve_default"] == ["routine", "review"] and out["risk_rules"]["high_paths"] == list(synthe_risk.HIGH_PATHS)
    assert b.op_lane_template_draft({"receiver": "builder"}, None)["lineage"] == lanes.lineage(w.cfg, w.registry, "builder")
    with pytest.raises(sb.Refused):
        b.op_lane_template_draft({"receiver": "builder", "auto_approve": ["urgent"]}, None)


# ---- the defaults for new grants, and standing lanes (no use limit, no expiry) -----------------------

def test_new_grants_default_to_routine_and_review_so_only_high_risk_interrupts(w):
    assert lanes.default_auto_approve() == lanes.default_auto_approve(DELEGATE) == ["routine", "review"]
    lanes.submit(w.cfg, grant(w, auto_approve=lanes.default_auto_approve()))
    assert push(w, {"package.json": "{}\n"})[3]["decision"] == "executed"
    assert push(w, {"src/x.py": "x\n"}, key="k2", delete=("src/app.py",))[3]["decision"] == "executed"
    *_, r = push(w, {WORKFLOW: "on: push\n"}, key="k3")
    assert r["decision"] == "staged" and r["risk"]["tier"] == "high"


def standing(w, **updates):
    body = {k: v for k, v in grant(w, auto_approve=lanes.DEFAULT_AUTO_APPROVE).items()
            if k not in ("approver", "kid", "sig", "max_uses", "expires_at")}
    body.update(updates)
    return lanes.sign(body, w.keys["rishab"])


def test_a_grant_that_omits_its_limits_stands_until_revoked(w):
    lanes.submit(w.cfg, standing(w))
    [t] = lanes.view(w.cfg)["templates"]
    assert t["status"] == "active" and t["uses_left"] is None and "expires_at" not in t
    for i in range(5):  # more than any default limit: uses are still counted, never capped
        *_, sha, r = push(w, {"src/app.py": f"print({i})\n"}, key=f"k{i}", branch=f"feature/{i}")
        assert r["decision"] == "executed" and r["lane_template"]["use"] == i + 1, r
        assert r["lane_template"]["expires_at"] is None and r["lane_template"]["max_uses"] is None
    assert push(w, {WORKFLOW: "on: push\n"}, key="k9", branch="feature/9")[3]["decision"] == "staged"
    lanes.revoke(w.cfg, lanes.sign({"template_id": "lane-1"}, w.keys["rishab"], True))
    assert lanes.view(w.cfg)["templates"][0]["status"] == "template_revoked"
    *_, r = push(w, {"src/app.py": "z\n"}, key="k10", branch="feature/10")  # no grant applies: a human must
    assert r["decision"] == "denied" and codes(r) & cm.APPROVAL_CODES and w.remote_ref("feature/10") is None


@pytest.mark.parametrize("field,value", [("max_uses", None), ("max_uses", 0), ("max_uses", "5"), ("max_uses", True),
                                         ("max_uses", lanes.MAX_USES + 1), ("expires_at", None), ("expires_at", ""),
                                         ("expires_at", 0)])
def test_a_limit_that_is_present_must_be_well_formed(w, field, value):
    with pytest.raises(cm.Deny, match="template malformed"):
        lanes.submit(w.cfg, standing(w, **{field: value}))


def test_present_limits_are_enforced_as_before_and_dropping_one_breaks_the_signature(w):
    with pytest.raises(cm.Deny, match="template expired"):
        lanes.submit(w.cfg, standing(w, expires_at="not a time"))
    x = standing(w, max_uses=1)
    del x["max_uses"]  # stripping a signed limit would make the lane unlimited
    with pytest.raises(cm.Deny, match="signature invalid"):
        lanes.submit(w.cfg, x)
    lanes.submit(w.cfg, standing(w, max_uses=1))
    assert push(w, {"src/app.py": "1\n"})[3]["decision"] == "executed"
    assert lanes.view(w.cfg)["templates"][0]["status"] == "template_exhausted"
    *_, r = push(w, {"src/app.py": "2\n"}, key="k2", branch="feature/y")
    assert r["decision"] == "denied" and codes(r) & cm.APPROVAL_CODES and w.remote_ref("feature/y") is None


def test_a_delegate_approval_under_a_standing_grant_still_lasts_at_most_an_hour(w):
    lanes.submit(w.cfg, standing(w, delegate=DELEGATE))
    *_, sha, r = push(w, {"src/app.py": "1\n"}, wait=True)
    assert staged(w)["waiting_for"] == ["approval", "review"]
    long = lanes.sign_delegate({"template_id": "lane-1", "idempotency_key": "k1", "from": "planner", "to": "builder",
                                "action": PUSH, "params": {"remote": "origin", "branch": "feature/x", "commit": sha},
                                "note": "fine", "expires_at": ts(dt.timedelta(minutes=61))}, w.keys[DELEGATE])
    assert "delegate_approval_too_long" in codes(cm.submit_delegate(w.cfg, long)["receipt"])
    [c] = cm.submit_delegate(w.cfg, delegate_doc(w, sha))["commits"]
    assert c["decision"] == "executed"


# ---- a push the lane's paths don't cover goes to a human; the receiver policy still denies -------------

@pytest.mark.parametrize("tiers", [("routine", "review"), None])  # risk-aware, and a grant without the field
def test_paths_outside_the_lane_wait_for_a_human_then_a_human_ships_it(w, tiers):
    lanes.submit(w.cfg, grant(w, auto_approve=tiers, path_scope=["src/**"]))
    p, _, sha, r = push(w, {"tests/test_app.py": "assert True\n", "src/app.py": "print('v2')\n"})
    assert r["decision"] == "staged" and {"outside_lane_paths", "staged"} <= codes(r), r
    assert codes(r) & cm.APPROVAL_CODES and "risk_escalated" not in codes(r)
    scope = r["lane_scope"]
    assert (scope["template_id"], scope["outside_paths"], scope["outside_count"], scope["commit"]) == \
        ("lane-1", ["tests/test_app.py"], 1, sha)
    msg = [x["message"] for x in r["reasons"] if x["code"] == "outside_lane_paths"][0]
    assert "needs a human" in msg and "tests/test_app.py" in msg
    assert staged(w)["waiting_for"] == ["approval", "scope"] and staged(w)["lane_scope"]["outside_count"] == 1
    assert cm.staged_detail(w.cfg, f"k1/{PUSH}")["lane_scope"]["outside_paths"] == ["tests/test_app.py"]
    assert w.remote_ref("feature/x") is None and uses_left(w) == 3
    n = len(w.chain()["receipts"])
    assert cm.retry_staged(w.cfg, sweep=True) == [] and len(w.chain()["receipts"]) == n
    [c] = human(w, p, sha)["commits"]
    assert c["decision"] == "executed" and c["approvals"][0]["approver"] == "rishab", c
    assert w.remote_ref("feature/x") == sha and uses_left(w) == 3 and w.chain()["ok"]


def test_outside_the_lane_with_a_delegate_the_delegate_is_not_asked(w):
    lanes.submit(w.cfg, grant(w, path_scope=["src/**"], delegate=DELEGATE))
    *_, sha, r = push(w, {"tests/t.py": "x\n"}, wait=True)
    assert r["staged"]["waiting_for"] == ["approval", "scope"] and "delegate_approval_missing" not in codes(r)
    out = cm.submit_delegate(w.cfg, delegate_doc(w, sha))
    assert "outside_lane_paths" in codes(out["receipt"]) and w.remote_ref("feature/x") is None


@pytest.mark.parametrize("path,code", [("src/secrets/key.txt", "path_forbidden"),
                                       ("README.md", "path_outside_scope")])
def test_paths_the_receiver_policy_refuses_are_still_denied_whoever_approves(w, path, code):
    lanes.submit(w.cfg, grant(w, path_scope=["src/**"]))
    p, tok, sha, r = push(w, {path: "x\n"})
    assert r["decision"] == "denied" and code in codes(r) and "outside_lane_paths" not in codes(r), r
    assert cm.staged_view(w.cfg) == [] and uses_left(w) == 3
    # a human's approval can't widen the receiver policy either: approved, re-proposed, still denied
    assert human(w, p, sha)["receipt"]["decision"] == "approval_accepted"
    again = w.propose(p, tok, sha)
    assert again["approvals"][0]["approver"] == "rishab", again
    assert again["decision"] == "denied" and code in codes(again) and w.remote_ref("feature/x") is None
