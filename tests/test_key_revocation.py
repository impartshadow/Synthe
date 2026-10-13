"""Key revocation (build queue item 2), v2.

A revocation list in the registry, each record signed by a designated
revocation operator key, consulted on every signature verification:
a packet or approval signed with a revoked key fails closed even when the
signature itself is valid.

v2 fixes two fail-open bugs from the v1 draft:
  A. revocation was keyed on kid alone: revoking worker/k1 also killed
     boss/k1. Revocation is now scoped to (agent, kid).
  B. past revocations stopped authenticating when the operator key that
     signed them left the registry: a routine rotation brought revoked keys
     back to life. Retired operator public keys now live in
     revocation.past_operators (verify-only for old records); the
     `rotate-operator` ceremony maintains it.
"""
import datetime as dt
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import handoff_check as hc      # noqa: E402
import synthe_crypto as sc      # noqa: E402
import synthe_sign as ss        # noqa: E402

NOW = dt.datetime.now(dt.timezone.utc).isoformat()


def _entry(secret: bytes, kid: str) -> dict:
    return {"kid": kid, "alg": sc.ALG, "public_key": sc.b64u(sc.public_key(secret))}


@pytest.fixture
def keys():
    return {"op": sc.generate_secret(), "op2": sc.generate_secret(),
            "worker": sc.generate_secret(), "boss": sc.generate_secret(),
            "attacker": sc.generate_secret()}


@pytest.fixture
def reg(keys):
    return {"agents": {
        "ops": {"keys": [_entry(keys["op"], "ops-1")]},
        "worker": {"keys": [_entry(keys["worker"], "worker-1")]},
    }}


def revoke(reg, keys, kid="worker-1", agent="worker", reason="leak", at=NOW):
    """An operator-signed revocation record appended to the registry, returned."""
    rec = sc.sign_revocation(sc.make_revocation(agent, kid, at, reason, "ops-1"), keys["op"])
    sec = reg.setdefault("revocation", {"operator": {"agent": "ops", "kid": "ops-1"}})
    sec.setdefault("revoked_kids", []).append(rec)
    return rec


def signed_packet(keys, agent="worker", kid="worker-1", secret=None):
    secret = keys["worker"] if secret is None else secret
    h = {"id": "h1", "from": agent, "to": "ops", "idempotency_key": "k1"}
    packet = {"handoff": h}
    return ss.sign_packet(packet, {"agent": agent, "kid": kid, "_secret": secret})


def check_sig(packet, reg):
    reasons, info = [], {}
    hc._verify_packet_signature(packet, packet["handoff"], reg, None, reasons, info)
    return [r["code"] for r in reasons], info


# ---- record authentication -------------------------------------------------

def test_record_authenticates_and_tampering_breaks_it(reg, keys):
    rec = revoke(reg, keys)
    assert sc.verify_revocation_record(reg, rec)
    assert sc.kid_is_revoked(reg, "worker", "worker-1")
    assert not sc.kid_is_revoked(reg, "worker", "worker-2")
    tampered = dict(rec, reason="just kidding")
    assert not sc.verify_revocation_record(reg, tampered)


def test_record_signed_by_non_operator_does_not_revoke(reg, keys):
    rec = sc.sign_revocation(sc.make_revocation("worker", "worker-1", NOW, "x", "ops-1"),
                             keys["attacker"])  # not the operator key
    reg.setdefault("revocation", {"operator": {"agent": "ops", "kid": "ops-1"}})
    reg["revocation"].setdefault("revoked_kids", []).append(rec)
    assert not sc.verify_revocation_record(reg, rec)
    # Unauthenticated, but enforced anyway: a registry writer could delete the
    # key outright, so honoring the record costs nothing (fail closed)...
    assert sc.kid_is_revoked(reg, "worker", "worker-1")
    assert sc.revocation_problems(reg)  # ...and the operator is told its issuer is unproven


def test_no_operator_designated_still_revokes_and_is_flagged(keys):
    reg = {"agents": {"worker": {"keys": [_entry(keys["worker"], "worker-1")]}}}
    rec = sc.sign_revocation(sc.make_revocation("worker", "worker-1", NOW, "x", "ops-1"),
                             keys["op"])
    reg["revocation"] = {"revoked_kids": [rec]}  # no operator designated
    assert sc.kid_is_revoked(reg, "worker", "worker-1")  # fail closed
    assert sc.revocation_problems(reg)


def test_record_signed_by_nondesignated_operator_key_is_rejected(reg, keys):
    # The operator agent has two keys; only the designated kid may sign.
    reg["agents"]["ops"]["keys"].append(_entry(keys["op2"], "ops-9"))
    rec = sc.sign_revocation(sc.make_revocation("worker", "worker-1", NOW, "x", "ops-9"),
                             keys["op2"])
    reg.setdefault("revocation", {"operator": {"agent": "ops", "kid": "ops-1"}})
    reg["revocation"].setdefault("revoked_kids", []).append(rec)
    assert not sc.verify_revocation_record(reg, rec)
    assert sc.kid_is_revoked(reg, "worker", "worker-1")  # unauthenticated, enforced anyway
    assert sc.revocation_problems(reg)


def test_record_must_name_the_single_key_when_operator_kid_omitted(reg, keys):
    reg["revocation"] = {"operator": {"agent": "ops"}, "revoked_kids": []}  # no kid
    rec = sc.sign_revocation(sc.make_revocation("worker", "worker-1", NOW, "x", "ops-1"),
                             keys["op"])
    reg["revocation"]["revoked_kids"].append(rec)
    assert sc.verify_revocation_record(reg, rec)  # ops has exactly one key: ops-1
    reg["agents"]["ops"]["keys"].append(_entry(keys["op2"], "ops-9"))  # now ambiguous
    assert not sc.verify_revocation_record(reg, rec)


# ---- Bug A: revocation is scoped to (agent, kid) -----------------------------

def test_revocation_scoped_to_agent_not_kid_string(keys):
    reg = {"agents": {
        "ops": {"keys": [_entry(keys["op"], "ops-1")]},
        "worker": {"keys": [_entry(keys["worker"], "k1")]},
        "boss": {"keys": [_entry(keys["boss"], "k1")]},  # same kid string
    }}
    rec = sc.sign_revocation(sc.make_revocation("worker", "k1", NOW, "leak", "ops-1"),
                             keys["op"])
    reg["revocation"] = {"operator": {"agent": "ops", "kid": "ops-1"},
                         "revoked_kids": [rec]}
    assert sc.kid_is_revoked(reg, "worker", "k1")
    assert not sc.kid_is_revoked(reg, "boss", "k1")
    assert sc.find_key(reg, "boss", "k1") is not None  # boss's key still resolves
    assert sc.find_key(reg, "worker", "k1") is None
    assert sc.usable_keys(reg, "boss") == ["k1"]


def test_packet_from_other_agent_with_same_kid_still_verifies(keys):
    reg = {"agents": {
        "ops": {"keys": [_entry(keys["op"], "ops-1")]},
        "worker": {"keys": [_entry(keys["worker"], "k1")]},
        "boss": {"keys": [_entry(keys["boss"], "k1")]},
    }}
    boss_packet = signed_packet(keys, agent="boss", kid="k1", secret=keys["boss"])
    codes, _ = check_sig(boss_packet, reg)
    assert codes == []
    rec = sc.sign_revocation(sc.make_revocation("worker", "k1", NOW, "leak", "ops-1"),
                             keys["op"])
    reg["revocation"] = {"operator": {"agent": "ops", "kid": "ops-1"},
                         "revoked_kids": [rec]}
    codes, _ = check_sig(boss_packet, reg)
    assert codes == []  # boss is unaffected by worker's revocation
    worker_packet = signed_packet(keys, agent="worker", kid="k1", secret=keys["worker"])
    codes, _ = check_sig(worker_packet, reg)
    assert codes == ["signature_key_revoked"]


def test_approval_from_other_agent_with_same_kid_still_verifies(keys):
    reg = {"agents": {
        "ops": {"keys": [_entry(keys["op"], "ops-1")]},
        "worker": {"keys": [_entry(keys["worker"], "k1")]},
        "boss": {"keys": [_entry(keys["boss"], "k1")]},
    }}
    h = {"id": "h1", "from": "boss", "to": "ops", "idempotency_key": "k1"}
    appr = {"action": "push", "approver": "boss", "kid": "k1",
            "budget": {"tokens": 1000, "usd": 5, "minutes": 60}}  # v2 approvals bind a budget
    appr["sig"] = sc.b64u(sc.sign_bytes(keys["boss"], sc.approval_signing_input(appr, h)))
    rec = sc.sign_revocation(sc.make_revocation("worker", "k1", NOW, "leak", "ops-1"),
                             keys["op"])
    reg["revocation"] = {"operator": {"agent": "ops", "kid": "ops-1"},
                         "revoked_kids": [rec]}
    at = dt.datetime.now(dt.timezone.utc)
    assert hc._approval_ok("push", [appr], h, reg, {"require_signed_approvals": True}, at) == []


# ---- fail-closed verification ----------------------------------------------

def test_packet_signed_with_revoked_kid_fails_closed(reg, keys):
    packet = signed_packet(keys)
    codes, info = check_sig(packet, reg)
    assert codes == [] and info["signature"] == "verified"
    revoke(reg, keys)
    codes, info = check_sig(packet, reg)
    assert codes == ["signature_key_revoked"]
    assert info.get("signature") != "verified"


def test_find_key_returns_none_for_revoked_kid(reg, keys):
    assert sc.find_key(reg, "worker", "worker-1") is not None
    revoke(reg, keys)
    assert sc.find_key(reg, "worker", "worker-1") is None


def test_usable_keys_excludes_revoked(reg, keys):
    reg["agents"]["worker"]["keys"].append(_entry(keys["worker"], "worker-2"))
    assert sc.usable_keys(reg, "worker") == ["worker-1", "worker-2"]
    revoke(reg, keys)
    assert sc.usable_keys(reg, "worker") == ["worker-2"]


def _signed_approval(keys, kid="worker-1"):
    h = {"id": "h1", "from": "worker", "to": "ops", "idempotency_key": "k1"}
    appr = {"action": "push", "approver": "worker", "kid": kid,
            "budget": {"tokens": 1000, "usd": 5, "minutes": 60}}  # v2 approvals bind a budget
    appr["sig"] = sc.b64u(sc.sign_bytes(keys["worker"], sc.approval_signing_input(appr, h)))
    return h, appr


def test_approval_signed_with_revoked_kid_fails_closed(reg, keys):
    h, appr = _signed_approval(keys)
    at = dt.datetime.now(dt.timezone.utc)
    assert hc._approval_ok("push", [appr], h, reg, {"require_signed_approvals": True}, at) == []
    revoke(reg, keys)
    problems = hc._approval_ok("push", [appr], h, reg, {"require_signed_approvals": True}, at)
    assert [c for c, _ in problems] == ["approval_key_revoked"]


def test_verify_approval_fails_closed_directly(reg, keys):
    h, appr = _signed_approval(keys)
    msg = sc.approval_signing_input(appr, h)
    assert sc.verify_approval(reg, "worker", "worker-1", msg, sc.unb64u(appr["sig"]))
    revoke(reg, keys)
    assert not sc.verify_approval(reg, "worker", "worker-1", msg, sc.unb64u(appr["sig"]))


# ---- Bug B: revocation survives operator-key rotation -----------------------

def _rotate(reg, keys):
    """Simulate rotating ops-1 out of the registry (ops-2 takes over)."""
    reg["agents"]["ops"]["keys"] = [_entry(keys["op2"], "ops-2")]
    reg["revocation"]["operator"] = {"agent": "ops", "kid": "ops-2"}


def test_revocation_survives_operator_rotation_with_past_operators(reg, keys):
    packet = signed_packet(keys)
    revoke(reg, keys)
    codes, _ = check_sig(packet, reg)
    assert codes == ["signature_key_revoked"]
    _rotate(reg, keys)
    # retire ops-1's public key: old records keep authenticating
    reg["revocation"]["past_operators"] = [{
        "agent": "ops", "kid": "ops-1",
        "public_key": sc.b64u(sc.public_key(keys["op"])),
        "retired_at": NOW, "reason": "routine rotation"}]
    codes, _ = check_sig(packet, reg)
    assert codes == ["signature_key_revoked"]
    assert sc.revocation_problems(reg) == []


def test_hand_edited_rotation_never_unrevokes(reg, keys):
    # Retiring the operator key by hand, without keeping its public key in
    # past_operators: the old record no longer authenticates, but the key it
    # revoked stays revoked (fail closed) and the operator is told.
    revoke(reg, keys)
    assert sc.kid_is_revoked(reg, "worker", "worker-1")
    _rotate(reg, keys)
    assert sc.kid_is_revoked(reg, "worker", "worker-1")
    assert sc.revocation_problems(reg)


def test_retired_operator_key_cannot_issue_new_revocations(reg, keys):
    revoke(reg, keys)
    _rotate(reg, keys)
    reg["revocation"]["past_operators"] = [{
        "agent": "ops", "kid": "ops-1",
        "public_key": sc.b64u(sc.public_key(keys["op"])),
        "retired_at": NOW, "reason": "routine rotation"}]
    # a NEW record signed by the retired key does not authenticate: its
    # revoked_at is later than the retirement
    later = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)).isoformat()
    new = sc.sign_revocation(sc.make_revocation("ops", "ops-2", later, "x", "ops-1"),
                             keys["op"])
    assert not sc.verify_revocation_record(reg, new)
    # but one signed by the current operator does
    new2 = sc.sign_revocation(sc.make_revocation("ops", "ops-2", NOW, "x", "ops-2"),
                              keys["op2"])
    assert sc.verify_revocation_record(reg, new2)


# ---- CLI -------------------------------------------------------------------

def _key_file(path: Path, agent: str, kid: str, secret: bytes) -> Path:
    path.write_text(json.dumps({"agent": agent, "kid": kid, "alg": sc.ALG,
                                "private_key": sc.b64u(secret)}))
    return path


def test_revoke_kid_cli_end_to_end(tmp_path, keys):
    regp = tmp_path / "registry.json"
    reg = {"agents": {"ops": {"keys": [_entry(keys["op"], "ops-1")]},
                      "worker": {"keys": [_entry(keys["worker"], "worker-1")]}}}
    regp.write_text(json.dumps(reg))
    opkey = _key_file(tmp_path / "ops.key.json", "ops", "ops-1", keys["op"])
    rc = ss.main(["revoke-kid", "--registry", str(regp), "--agent", "worker",
                  "--kid", "worker-1", "--operator-key", str(opkey),
                  "--reason", "leaked in CI logs"])
    assert rc == 0
    reg2 = json.loads(regp.read_text())
    assert sc.kid_is_revoked(reg2, "worker", "worker-1")
    rec = reg2["revocation"]["revoked_kids"][0]
    assert rec["reason"] == "leaked in CI logs" and rec["operator_kid"] == "ops-1"
    # idempotent: second revoke is a no-op with one record
    assert ss.main(["revoke-kid", "--registry", str(regp), "--agent", "worker",
                    "--kid", "worker-1", "--operator-key", str(opkey)]) == 0
    assert len(json.loads(regp.read_text())["revocation"]["revoked_kids"]) == 1
    # a packet signed with the revoked kid now fails `verify` as REVOKED
    pktp = tmp_path / "packet.json"
    pktp.write_text(json.dumps(signed_packet(keys)))
    rc = ss.main(["verify", str(pktp), "--registry", str(regp)])
    assert rc == 2
    # and the audit listing shows it with no problems
    assert ss.main(["revocations", "--registry", str(regp)]) == 0


def test_revoke_kid_cli_refuses_unknown_kid(tmp_path, keys):
    regp = tmp_path / "registry.json"
    regp.write_text(json.dumps({"agents": {"ops": {"keys": [_entry(keys["op"], "ops-1")]},
                                          "worker": {"keys": [_entry(keys["worker"], "worker-1")]}}}))
    opkey = _key_file(tmp_path / "ops.key.json", "ops", "ops-1", keys["op"])
    with pytest.raises(SystemExit):
        ss.main(["revoke-kid", "--registry", str(regp), "--agent", "worker",
                 "--kid", "worker-9", "--operator-key", str(opkey)])
    assert not sc.kid_is_revoked(json.loads(regp.read_text()), "worker", "worker-1")


def test_revoke_kid_cli_refuses_wrong_operator(tmp_path, keys):
    regp = tmp_path / "registry.json"
    regp.write_text(json.dumps({
        "agents": {"ops": {"keys": [_entry(keys["op"], "ops-1")]},
                   "worker": {"keys": [_entry(keys["worker"], "worker-1")]}},
        "revocation": {"operator": {"agent": "ops", "kid": "ops-1"}, "revoked_kids": []}}))
    mallory = _key_file(tmp_path / "mallory.key.json", "mallory", "mallory-1", keys["attacker"])
    with pytest.raises(SystemExit):
        ss.main(["revoke-kid", "--registry", str(regp), "--agent", "worker",
                 "--kid", "worker-1", "--operator-key", str(mallory)])
    assert not sc.kid_is_revoked(json.loads(regp.read_text()), "worker", "worker-1")


def test_revoke_kid_cli_scopes_records_to_agent(tmp_path, keys):
    # Same kid string on two agents: revoking one leaves the other's record
    # (and key) alone, and the CLI can revoke the second independently.
    regp = tmp_path / "registry.json"
    regp.write_text(json.dumps({
        "agents": {"ops": {"keys": [_entry(keys["op"], "ops-1")]},
                   "worker": {"keys": [_entry(keys["worker"], "k1")]},
                   "boss": {"keys": [_entry(keys["boss"], "k1")]}}}))
    opkey = _key_file(tmp_path / "ops.key.json", "ops", "ops-1", keys["op"])
    assert ss.main(["revoke-kid", "--registry", str(regp), "--agent", "worker",
                    "--kid", "k1", "--operator-key", str(opkey)]) == 0
    reg2 = json.loads(regp.read_text())
    assert sc.kid_is_revoked(reg2, "worker", "k1")
    assert not sc.kid_is_revoked(reg2, "boss", "k1")
    assert ss.main(["revoke-kid", "--registry", str(regp), "--agent", "boss",
                    "--kid", "k1", "--operator-key", str(opkey)]) == 0
    reg3 = json.loads(regp.read_text())
    assert sc.kid_is_revoked(reg3, "worker", "k1")
    assert sc.kid_is_revoked(reg3, "boss", "k1")
    assert len(reg3["revocation"]["revoked_kids"]) == 2


def test_revoked_operator_key_cannot_issue_revocations(tmp_path, keys):
    regp = tmp_path / "registry.json"
    reg = {"agents": {"ops": {"keys": [_entry(keys["op"], "ops-1")]},
                      "worker": {"keys": [_entry(keys["worker"], "worker-1"),
                                          _entry(keys["worker"], "worker-2")]}}}
    regp.write_text(json.dumps(reg))
    opkey = _key_file(tmp_path / "ops.key.json", "ops", "ops-1", keys["op"])
    # first revoke worker-1 (designates the operator), then the operator key itself
    assert ss.main(["revoke-kid", "--registry", str(regp), "--agent", "worker",
                    "--kid", "worker-1", "--operator-key", str(opkey)]) == 0
    assert ss.main(["revoke-kid", "--registry", str(regp), "--agent", "ops",
                    "--kid", "ops-1", "--operator-key", str(opkey)]) == 0
    reg2 = json.loads(regp.read_text())
    assert sc.kid_is_revoked(reg2, "ops", "ops-1")
    # past revocations still authenticate...
    assert sc.kid_is_revoked(reg2, "worker", "worker-1")
    # ...but the revoked operator key cannot sign new ones
    with pytest.raises(SystemExit):
        ss.main(["revoke-kid", "--registry", str(regp), "--agent", "worker",
                 "--kid", "worker-2", "--operator-key", str(opkey)])


def test_rotate_operator_cli_end_to_end(tmp_path, keys):
    regp = tmp_path / "registry.json"
    regp.write_text(json.dumps({
        "agents": {"ops": {"keys": [_entry(keys["op"], "ops-1"),
                                    _entry(keys["op2"], "ops-2")]},
                   "worker": {"keys": [_entry(keys["worker"], "worker-1"),
                                        _entry(keys["worker"], "worker-2")]}},
        "revocation": {"operator": {"agent": "ops", "kid": "ops-1"}, "revoked_kids": []}}))
    opkey = _key_file(tmp_path / "ops.key.json", "ops", "ops-1", keys["op"])
    op2key = _key_file(tmp_path / "ops2.key.json", "ops", "ops-2", keys["op2"])
    # revoke worker-1 under the old operator, then rotate
    assert ss.main(["revoke-kid", "--registry", str(regp), "--agent", "worker",
                    "--kid", "worker-1", "--operator-key", str(opkey)]) == 0
    assert ss.main(["rotate-operator", "--registry", str(regp),
                    "--operator-key", str(opkey), "--new-operator-key", str(op2key),
                    "--reason", "routine rotation"]) == 0
    reg2 = json.loads(regp.read_text())
    assert reg2["revocation"]["operator"] == {"agent": "ops", "kid": "ops-2"}
    past = reg2["revocation"]["past_operators"]
    assert len(past) == 1 and past[0]["kid"] == "ops-1"
    assert past[0]["public_key"] == sc.b64u(sc.public_key(keys["op"]))
    # the old revocation survives the rotation
    assert sc.kid_is_revoked(reg2, "worker", "worker-1")
    assert sc.revocation_problems(reg2) == []
    # the old key can no longer issue revocations; the new one can
    with pytest.raises(SystemExit):
        ss.main(["revoke-kid", "--registry", str(regp), "--agent", "worker",
                 "--kid", "worker-2", "--operator-key", str(opkey)])
    assert ss.main(["revoke-kid", "--registry", str(regp), "--agent", "worker",
                    "--kid", "worker-2", "--operator-key", str(op2key)]) == 0
    assert sc.kid_is_revoked(json.loads(regp.read_text()), "worker", "worker-2")


def test_rotate_operator_refuses_unregistered_new_key(tmp_path, keys):
    regp = tmp_path / "registry.json"
    regp.write_text(json.dumps({
        "agents": {"ops": {"keys": [_entry(keys["op"], "ops-1")]}},
        "revocation": {"operator": {"agent": "ops", "kid": "ops-1"}, "revoked_kids": []}}))
    opkey = _key_file(tmp_path / "ops.key.json", "ops", "ops-1", keys["op"])
    ghost = _key_file(tmp_path / "ghost.key.json", "ops", "ops-9", keys["op2"])
    with pytest.raises(SystemExit):
        ss.main(["rotate-operator", "--registry", str(regp),
                 "--operator-key", str(opkey), "--new-operator-key", str(ghost)])
    reg2 = json.loads(regp.read_text())
    assert reg2["revocation"]["operator"] == {"agent": "ops", "kid": "ops-1"}


def test_rotate_operator_refuses_same_key(tmp_path, keys):
    regp = tmp_path / "registry.json"
    regp.write_text(json.dumps({
        "agents": {"ops": {"keys": [_entry(keys["op"], "ops-1")]}},
        "revocation": {"operator": {"agent": "ops", "kid": "ops-1"}, "revoked_kids": []}}))
    opkey = _key_file(tmp_path / "ops.key.json", "ops", "ops-1", keys["op"])
    with pytest.raises(SystemExit):
        ss.main(["rotate-operator", "--registry", str(regp),
                 "--operator-key", str(opkey), "--new-operator-key", str(opkey)])


def test_stale_synthe_crypto_fails_closed_not_crash(reg, keys, monkeypatch):
    # An older synthe_crypto.py next to a newer checker (no kid_is_revoked)
    # must fail closed with a named reason, not raise AttributeError.
    import types
    stale = types.ModuleType("synthe_crypto")
    for name in dir(sc):
        if name != "kid_is_revoked":
            setattr(stale, name, getattr(sc, name))
    monkeypatch.setitem(sys.modules, "synthe_crypto", stale)
    codes, _ = check_sig(signed_packet(keys), reg)
    assert codes == ["signature_unsupported"]


def test_verify_cli_exits_nonzero_on_unauthenticated_revocation(reg, keys, tmp_path, capsys):
    packet = signed_packet(keys, kid="worker-1")
    forged = sc.sign_revocation(sc.make_revocation("worker", "worker-9", NOW, "x", "ops-1"),
                                keys["attacker"])
    reg["revocation"] = {"operator": {"agent": "ops", "kid": "ops-1"}, "revoked_kids": [forged]}
    (tmp_path / "p.json").write_text(json.dumps(packet))
    (tmp_path / "r.json").write_text(json.dumps(reg))
    assert ss.main(["verify", str(tmp_path / "p.json"), "--registry", str(tmp_path / "r.json")]) == 2
    assert "revocation_problems" in capsys.readouterr().out
