"""Approvals bind the budget (build-queue item 3).

v2 approvals pin the `authority.budget` (tokens/usd/minutes) and the approved
action's cost estimates (`est_tokens`/`est_usd`/`est_minutes`) the approver
reviewed, as signed ceilings: afterwards the packet's spend may only come
down, never up. Approvals signed under the retired v1 scheme fail closed with
`approval_version_unsupported`, never as a confusing `approval_signature_invalid`.

Rework (reviewer finding): the v1 patch pinned nothing when the packet named
no explicit budget (relying on receiver defaults), so a v2 approval with no
budget pin capped nothing. Now signing is REFUSED unless a complete budget can
be bound -- the approver's explicit budget, the packet's own budget, and the
receiver policy's defaults.budget merged per dimension (the EFFECTIVE budget
the checker will apply) -- and a v2 approval carrying no budget pin is
REJECTED outright (`approval_budget_missing`): it caps nothing, so it
authorizes nothing.
"""
import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import handoff_check as hc  # noqa: E402
import synthe_crypto as sc  # noqa: E402
import synthe_sign as ss  # noqa: E402
from world import World, cm  # noqa: E402

FAR = "2999-01-01T00:00:00Z"
BUDGET = {"tokens": 1000, "usd": 5, "minutes": 30}
# The test world's builder policy defaults: the effective budget the checker
# applies to the world's minimal (budget-less) packets.
DEFAULTS_BUDGET = {"tokens": 100000, "usd": 5, "minutes": 60}


@pytest.fixture
def w(tmp_path):
    return World(tmp_path)


def _approved_packet(w, budget=None, estimates=None, approver="rishab"):
    """A packet whose budget/estimates the approver pinned, sender-signed."""
    p = w.packet(approve=False)
    h = p["handoff"]
    h["authority"]["budget"] = dict(budget if budget is not None else BUDGET)
    if estimates:
        h["planned_actions"][1].update(estimates)
    ss.approve_packet(p, w.keys[approver], "push_branch", FAR)
    return ss.sign_packet(p, w.keys["planner"])


def _codes(w, packet):
    ok, reasons = hc.validate(packet, registry=w.registry, ledger={},
                              workspace=w.tmp / "workspace", at=hc.now_utc(), info={})
    return ok, {r["code"] for r in reasons}


# ---- the bind ---------------------------------------------------------------

def test_approval_pins_the_budget_and_estimates_it_reviews(w):
    p = _approved_packet(w, estimates={"est_usd": 2, "est_tokens": 100})
    appr = p["handoff"]["authority"]["approvals"][0]
    assert appr["budget"] == BUDGET
    assert appr["estimates"] == {"est_usd": 2, "est_tokens": 100}
    ok, codes = _codes(w, p)
    assert ok, codes


def test_signing_input_binds_budget_under_the_v2_domain(w):
    p = _approved_packet(w)
    appr = p["handoff"]["authority"]["approvals"][0]
    msg = sc.approval_signing_input(appr, p["handoff"])
    assert msg.startswith(b"synthe/approval-signature/v2\n")
    body = msg.split(b"\n", 1)[1].decode()
    assert '"budget":{"minutes":30,"tokens":1000,"usd":5}' in body.replace(" ", "")
    assert sc.verify_approval(w.registry, "rishab", appr["kid"], msg, sc.unb64u(appr["sig"]))


def test_budget_raised_after_approval_is_rejected(w):
    p = _approved_packet(w)
    raised = copy.deepcopy(p)
    raised["handoff"]["authority"]["budget"]["usd"] = 5000  # approved $5
    raised = ss.sign_packet(raised, w.keys["planner"])  # sender re-signs: still bound
    ok, codes = _codes(w, raised)
    assert not ok and "approval_budget_exceeded" in codes


def test_budget_lowered_after_approval_still_verifies(w):
    p = _approved_packet(w)
    lowered = copy.deepcopy(p)
    lowered["handoff"]["authority"]["budget"]["usd"] = 4  # under the $5 cap: fine
    lowered["handoff"]["planned_actions"][1].pop("est_usd", None)
    lowered = ss.sign_packet(lowered, w.keys["planner"])
    ok, codes = _codes(w, lowered)
    assert "approval_budget_exceeded" not in codes, codes


def test_estimates_raised_after_approval_are_rejected(w):
    p = _approved_packet(w, estimates={"est_usd": 2})
    raised = copy.deepcopy(p)
    raised["handoff"]["planned_actions"][1]["est_usd"] = 200  # approved $2
    raised = ss.sign_packet(raised, w.keys["planner"])
    ok, codes = _codes(w, raised)
    assert not ok and "approval_estimates_exceeded" in codes


def test_explicit_budget_cap_binds_tighter_than_the_packet(w):
    p = w.packet(approve=False)
    h = p["handoff"]
    h["authority"]["budget"] = {"tokens": 1000, "usd": 8, "minutes": 30}
    ss.approve_packet(p, w.keys["rishab"], "push_branch", FAR,
                      budget={"tokens": 1000, "usd": 5, "minutes": 30})
    appr = h["authority"]["approvals"][0]
    assert appr["budget"] == {"tokens": 1000, "usd": 5, "minutes": 30}
    ok, codes = _codes(w, ss.sign_packet(p, w.keys["planner"]))
    assert not ok and "approval_budget_exceeded" in codes


def test_detached_approval_binds_the_budget(w):
    p = w.packet(approve=False)
    p["handoff"]["authority"]["budget"] = dict(BUDGET)
    det = ss.detached_approval(p, w.keys["rishab"], "push_branch", FAR)
    assert det["budget"] == BUDGET
    assert det["idempotency_key"] == p["handoff"]["idempotency_key"]
    # Verified like an embedded one: the stub carries no budget, the pin does.
    stub = {"idempotency_key": det["idempotency_key"], "from": det["from"], "to": det["to"]}
    assert hc._approval_ok(det["action"], [det], stub, w.registry,
                           hc.receiver_policy(w.registry, det["to"]), hc.now_utc()) == []


# ---- cross-version behavior -------------------------------------------------

def _v1_signed_packet(w, tamper=False):
    """An approval signed under the retired v1 scheme (no budget binding)."""
    p = w.packet(approve=False)
    h = p["handoff"]
    h["authority"]["budget"] = dict(BUDGET)
    appr = {"action": "push_branch", "approver": "rishab", "expires_at": FAR,
            "params": ss.planned_params(h, "push_branch"), "kid": w.keys["rishab"]["kid"]}
    appr["sig"] = sc.b64u(sc.sign_bytes(w.keys["rishab"]["_secret"],
                                        sc.approval_signing_input_v1(appr, h)))
    if tamper:
        raw = bytearray(sc.unb64u(appr["sig"]))
        raw[0] ^= 1
        appr["sig"] = sc.b64u(bytes(raw))
    h["authority"]["approvals"] = [appr]
    return ss.sign_packet(p, w.keys["planner"])


def test_v1_approval_fails_closed_with_version_unsupported(w):
    ok, codes = _codes(w, _v1_signed_packet(w))
    assert not ok
    assert "approval_version_unsupported" in codes
    assert "approval_signature_invalid" not in codes


def test_v1_approval_with_params_pins_still_version_unsupported(w):
    # The v1 scheme did include params; that doesn't make it current.
    ok, codes = _codes(w, _v1_signed_packet(w))
    assert "approval_version_unsupported" in codes


def test_tampered_v1_approval_is_signature_invalid_not_version(w):
    ok, codes = _codes(w, _v1_signed_packet(w, tamper=True))
    assert not ok
    assert "approval_signature_invalid" in codes
    assert "approval_version_unsupported" not in codes


def test_v1_domain_is_retired_for_signing():
    assert sc.APPROVAL_SIG_DOMAIN == "synthe/approval-signature/v2"
    assert sc.APPROVAL_SIG_DOMAIN_V1 == "synthe/approval-signature/v1"


# ---- the approver sees the cap --------------------------------------------------

def test_approval_card_shows_the_budget_being_bound():
    sys.path.insert(0, str(ROOT / "src"))
    import synthe_approve as sa  # noqa: E402
    detail = {"id": "k1/push_branch", "from": "planner", "to": "builder",
              "effect": {"commit": "a" * 40, "remote": "origin", "branch": "feature/x",
                         "expected_old": "new"},
              "changes": {"available": False, "note": "n/a"},
              "packet": {"handoff": {"authority": {"budget": dict(BUDGET)}}}}
    out = sa.render(detail)
    assert "Budget" in out and "usd 5" in out
    # No budget on the packet: no line, no crash.
    detail["packet"]["handoff"]["authority"] = {}
    assert "Budget" not in sa.render(detail)


# ---- malformed pins fail fast ------------------------------------------------

def test_malformed_pinned_budget_is_invalid(w):
    p = _approved_packet(w)
    p["handoff"]["authority"]["approvals"][0]["budget"] = {"usd": "lots"}
    p = ss.sign_packet(p, w.keys["planner"])
    ok, codes = _codes(w, p)
    assert not ok and "malformed:authority.approvals[0].budget" in codes


def test_negative_pinned_estimate_is_invalid(w):
    p = _approved_packet(w, estimates={"est_usd": 2})
    p["handoff"]["authority"]["approvals"][0]["estimates"] = {"est_usd": -1}
    p = ss.sign_packet(p, w.keys["planner"])
    ok, codes = _codes(w, p)
    assert not ok and "malformed:authority.approvals[0].estimates" in codes


# ---- rework: no budget to bind -> signing is refused ------------------------

def _builder_policy(w):
    return (w.registry.get("agents") or {}).get("builder", {}).get("policy")


def test_signing_without_any_budget_is_refused(w):
    p = w.packet(approve=False)  # names no authority.budget
    assert "budget" not in p["handoff"]["authority"]
    with pytest.raises(ValueError, match="no budget to bind"):
        ss.approve_packet(p, w.keys["rishab"], "push_branch", FAR)
    with pytest.raises(ValueError, match="--budget"):
        ss.detached_approval(p, w.keys["rishab"], "push_branch", FAR)


def test_signing_with_policy_pins_the_effective_budget(w):
    p = w.packet(approve=False)
    ss.approve_packet(p, w.keys["rishab"], "push_branch", FAR, policy=_builder_policy(w))
    appr = p["handoff"]["authority"]["approvals"][0]
    assert appr["budget"] == DEFAULTS_BUDGET  # exactly what the checker will apply
    ok, codes = _codes(w, ss.sign_packet(p, w.keys["planner"]))
    assert ok, codes


def test_policy_fills_only_the_dimensions_the_packet_omits(w):
    p = w.packet(approve=False)
    p["handoff"]["authority"]["budget"] = {"tokens": 1000}  # partial packet budget
    ss.approve_packet(p, w.keys["rishab"], "push_branch", FAR, policy=_builder_policy(w))
    appr = p["handoff"]["authority"]["approvals"][0]
    assert appr["budget"] == {"tokens": 1000, "usd": 5, "minutes": 60}


def test_explicit_budget_wins_per_dimension(w):
    p = w.packet(approve=False)
    p["handoff"]["authority"]["budget"] = {"tokens": 1000, "usd": 8, "minutes": 30}
    ss.approve_packet(p, w.keys["rishab"], "push_branch", FAR, budget={"usd": 5})
    appr = p["handoff"]["authority"]["approvals"][0]
    assert appr["budget"] == {"tokens": 1000, "usd": 5, "minutes": 30}


def test_incomplete_or_invalid_budget_still_refused(w):
    p = w.packet(approve=False)
    p["handoff"]["authority"]["budget"] = {"tokens": 1000}
    with pytest.raises(ValueError, match="missing dimensions: usd, minutes"):
        ss.approve_packet(p, w.keys["rishab"], "push_branch", FAR)  # no policy: incomplete
    with pytest.raises(ValueError, match="must be non-negative numbers"):
        ss.approve_packet(p, w.keys["rishab"], "push_branch", FAR,
                          budget={"usd": "lots", "minutes": 30})


def test_cli_approve_without_a_budget_fails_telling_the_approver_to_name_one(w, tmp_path, capsys):
    p = w.packet(approve=False)
    pfile = tmp_path / "packet.json"
    pfile.write_text(json.dumps(p))
    k = w.keys["rishab"]
    kfile = tmp_path / "approver.key.json"
    kfile.write_text(json.dumps({kk: k[kk] for kk in ("agent", "kid", "alg", "private_key")}))
    rc = ss.main(["approve", str(pfile), "--key", str(kfile), "--action", "push_branch",
                  "--no-params", "--out", str(tmp_path / "out.json")])
    assert rc == 2
    assert "--budget" in capsys.readouterr().err
    # And with --budget it signs, pinning the named cap.
    rc = ss.main(["approve", str(pfile), "--key", str(kfile), "--action", "push_branch",
                  "--no-params", "--budget", '{"tokens": 100, "usd": 1, "minutes": 10}',
                  "--out", str(tmp_path / "out.json")])
    assert rc == 0
    out = json.loads((tmp_path / "out.json").read_text())
    assert out["handoff"]["authority"]["approvals"][0]["budget"] == {
        "tokens": 100, "usd": 1, "minutes": 10}


# ---- rework: a v2 approval with no budget pin is rejected -------------------

def _unpinned_v2_approval_packet(w):
    """A v2-signed approval that pins no budget. No tool mints these anymore;
    it stands in for a hand-built approval or one predating the rule."""
    p = w.packet(approve=False)
    h = p["handoff"]
    appr = {"action": "push_branch", "approver": "rishab", "expires_at": FAR,
            "kid": w.keys["rishab"]["kid"]}
    appr["sig"] = sc.b64u(sc.sign_bytes(w.keys["rishab"]["_secret"],
                                        sc.approval_signing_input(appr, h)))
    assert appr.get("budget") is None
    h["authority"]["approvals"] = [appr]
    return ss.sign_packet(p, w.keys["planner"])


def test_v2_approval_with_no_budget_pin_is_rejected(w):
    ok, codes = _codes(w, _unpinned_v2_approval_packet(w))
    assert not ok and "approval_budget_missing" in codes


def test_broker_rejects_budget_less_detached_approval_as_malformed(w):
    appr = _unpinned_v2_approval_packet(w)["handoff"]["authority"]["approvals"][0]
    det = {**appr, "idempotency_key": "k1", "from": "planner", "to": "builder"}
    out = cm.submit_approval(w.cfg, det)
    assert out["receipt"]["decision"] == "approval_rejected"
    assert "approval_malformed" in {r["code"] for r in out["receipt"]["reasons"]}


def test_verify_reports_unpinned_budget(w, tmp_path, capsys):
    p = _unpinned_v2_approval_packet(w)
    pfile = tmp_path / "p.json"
    pfile.write_text(json.dumps(p))
    rfile = tmp_path / "r.json"
    rfile.write_text(json.dumps(w.registry))
    assert ss.main(["verify", str(pfile), "--registry", str(rfile)]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["approvals"][0]["status"] == "UNPINNED_BUDGET"


# ---- rework: the terminal approval pins the broker's effective budget -------

def test_build_approval_pins_the_effective_budget(w):
    sys.path.insert(0, str(ROOT / "src"))
    import synthe_approve as sa  # noqa: E402
    detail = {"id": "k1/push_branch", "action": "push_branch",
              "effect": {"commit": "a" * 40, "remote": "origin", "branch": "feature/x",
                         "expected_old": "new"},
              "changes": {"available": False},
              "packet": w.packet(approve=False),  # minimal: names no budget
              "effective_budget": dict(DEFAULTS_BUDGET)}
    appr = sa.build_approval(detail, w.keys["rishab"], 30)
    assert appr["budget"] == DEFAULTS_BUDGET
    # The card shows the budget the approval will cap, not a blank line.
    assert "usd 5" in sa.render(detail)
