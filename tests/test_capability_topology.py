"""Declared-capability enforcement + role-scoped handoff topologies (v0.6).

Covers SPEC section 15 and the Oct 10 spec's Features B and C:
signed capability declarations enforced before actions execute
(`capability_not_declared`), team topologies with allowed edges
(`topology_violation`), founder-signed versioned topology declarations.
"""
import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import handoff_check as hc      # noqa: E402
import synthe_sign as ss        # noqa: E402

V3 = ROOT / "examples" / "v03"
KEYS = V3 / "test-keys"
FAR = "2999-01-01T00:00:00Z"
CADDY_TOOLS = ["read_repo", "run_tests", "gmail_send"]


def reg(**policy):
    r = json.loads((V3 / "registry.json").read_text())
    r["agents"]["caddy"]["policy"].update(policy)
    return r


def packet(key="k-cap", capability=None, sender_role=None, receiver_role=None,
           from_agent="cora"):
    """The public valid-signed packet with a fresh key, re-approved by rohan
    and re-signed by the sending agent, optionally carrying a capability
    declaration and team roles (re-signed afterwards, so the signature covers
    them). `from_agent` lets adversarial tests send as someone else."""
    p = json.loads((V3 / "packets" / "valid-signed.json").read_text())
    h = p["handoff"]
    h["idempotency_key"], h["id"] = key, f"h-{key}"
    h["from"] = from_agent
    h["authority"]["approvals"] = []
    if capability is not None:
        h["capability"] = capability
    if sender_role is not None:
        h["sender_role"] = sender_role
    if receiver_role is not None:
        h["receiver_role"] = receiver_role
    # Approvals bind a budget (approval signature v2); this packet names none.
    ss.approve_packet(p, ss.load_key(KEYS / "rohan.key.json"), "send_email", FAR,
                      budget={"tokens": 10**9, "usd": 10**6, "minutes": 10**6})
    return ss.sign_packet(p, ss.load_key(KEYS / f"{from_agent}.key.json"))


def ship_team(**kw):
    """The Oct 10 spec's example topology, signed by founder rohan. v2 binds
    agents to roles via `members` (signed, enforced): the test packets run
    from=cora/to=caddy unless a test says otherwise."""
    topo = {"version": "2026-10-12.1",
            "roles": ["ceo", "designer", "em", "qa", "release"],
            "edges": [["ceo", "designer"], ["designer", "em"], ["em", "qa"],
                      ["qa", "release"], ["qa", "em"]],
            "role_capabilities": {"qa": {"tools": CADDY_TOOLS}},
            "members": {"ceo": ["caddy", "rohan"], "designer": ["rohan"],
                        "em": ["cora"], "qa": ["cora", "caddy"],
                        "release": ["caddy"]}}
    topo.update(kw)
    return ss.sign_topology("ship-team", topo, ss.load_key(KEYS / "rohan.key.json"))


def reg_with_topology(topo=None, **policy):
    r = reg(topology="ship-team", **policy)
    r["topologies"] = {"ship-team": topo if topo is not None else ship_team()}
    return r


def check(p, registry=None, **kw):
    return hc.check(copy.deepcopy(p), registry=registry or reg(), ledger_path=None,
                    workspace=V3 / "workspace", dry_run=True, **kw)


def codes(v):
    return {r["code"] for r in v.get("reasons", [])}


def full_capability(**kw):
    cap = {"version": "2026-10-12.1", "env": ["OPENAI_API_KEY"],
           "paths": ["project/**"], "tools": CADDY_TOOLS,
           "network": False}
    cap.update(kw)
    return cap


# ---- capability declarations: admission-time enforcement --------------------
def test_capability_within_declaration_accepts():
    p = packet("k-c1", capability=full_capability())
    p["handoff"]["planned_actions"][0]["params"] = {
        "env": ["OPENAI_API_KEY"], "paths": ["project/a.txt"]}
    p = ss.sign_packet(p, ss.load_key(KEYS / "cora.key.json"))
    assert check(p)["decision"] == "ACCEPT"


def test_undeclared_env_read_rejected():
    """Oct 10 spec B.1: a skill reading an undeclared env var is rejected."""
    p = packet("k-c2", capability=full_capability())
    p["handoff"]["planned_actions"][0]["params"] = {"env": ["AWS_SECRET_ACCESS_KEY"]}
    p = ss.sign_packet(p, ss.load_key(KEYS / "cora.key.json"))
    v = check(p)
    assert v["decision"] == "REJECT" and v["state"] == "blocked"
    assert "capability_not_declared" in codes(v)


def test_write_outside_declared_paths_rejected():
    """Oct 10 spec B.2: a write outside declared paths is rejected before it lands."""
    p = packet("k-c3", capability=full_capability())
    p["handoff"]["planned_actions"][0]["params"] = {"paths": ["other/a.txt"]}
    p = ss.sign_packet(p, ss.load_key(KEYS / "cora.key.json"))
    v = check(p)
    assert v["decision"] == "REJECT" and "capability_not_declared" in codes(v)


def test_network_denied_by_default():
    """Oct 10 spec B.3: network egress is denied unless declared."""
    p = packet("k-c4", capability=full_capability())  # network: False
    p["handoff"]["planned_actions"][0]["params"] = {"network": True}
    p = ss.sign_packet(p, ss.load_key(KEYS / "cora.key.json"))
    v = check(p)
    assert v["decision"] == "REJECT" and "capability_not_declared" in codes(v)
    # ... and with no declaration at all, a networked action is still denied
    # as soon as any capability source is in force (here the policy ceiling).
    p = packet("k-c4b")
    p["handoff"]["planned_actions"][0]["params"] = {"network": True}
    p = ss.sign_packet(p, ss.load_key(KEYS / "cora.key.json"))
    v = check(p, registry=reg(capability={"network": False}))
    assert v["decision"] == "REJECT" and "capability_not_declared" in codes(v)


def test_network_declared_true_accepts():
    p = packet("k-c5", capability=full_capability(network=True))
    p["handoff"]["planned_actions"][0]["params"] = {"network": True}
    p = ss.sign_packet(p, ss.load_key(KEYS / "cora.key.json"))
    assert check(p)["decision"] == "ACCEPT"


def test_tool_outside_declaration_rejected():
    p = packet("k-c6", capability=full_capability(tools=["read_repo"]))
    v = check(p)  # planned actions use read_repo AND gmail_send
    assert v["decision"] == "REJECT" and "capability_not_declared" in codes(v)


def test_capability_may_narrow_but_not_widen_policy_ceiling():
    """Authority may only narrow: a declaration broader than the receiver's
    capability ceiling is capability_exceeds_receiver_policy (blocked)."""
    r = reg(capability={"tools": ["read_repo"], "network": False})
    p = packet("k-c7", capability=full_capability())  # claims gmail_send too
    v = check(p, registry=r)
    assert v["decision"] == "REJECT" and v["state"] == "blocked"
    assert "capability_exceeds_receiver_policy" in codes(v)


def test_capability_version_pin_mismatch():
    r = reg(capability={"version": "2026-10-12.1"})
    p = packet("k-c8", capability=full_capability(version="1999-01-01.0"))
    v = check(p, registry=r)
    assert v["decision"] == "REJECT" and "capability_exceeds_receiver_policy" in codes(v)


def test_capability_path_ceiling_uses_glob_coverage():
    r = reg(capability={"paths": ["project/**"]})
    p = packet("k-c9", capability=full_capability(paths=["project/sub/**"]))
    assert check(p, registry=r)["decision"] == "ACCEPT"
    p = packet("k-c10", capability=full_capability(paths=["other/**"]))
    v = check(p, registry=r)
    assert v["decision"] == "REJECT" and "capability_exceeds_receiver_policy" in codes(v)


def test_require_capability_declaration_missing():
    v = check(packet("k-c11"), registry=reg(require_capability_declaration=True))
    assert v["decision"] == "REJECT" and v["state"] == "invalid"
    assert "capability_declaration_missing" in codes(v)


def test_malformed_capability_is_invalid():
    p = packet("k-c12", capability={"env": ["A"]})  # version missing
    v = check(p)
    assert v["decision"] == "REJECT" and v["state"] == "invalid"
    assert "malformed:capability.version" in codes(v)


def test_no_declaration_no_policy_stays_backward_compatible():
    """Declarations are optional unless a receiver policy requires them."""
    v = check(packet("k-c13"))
    assert v["decision"] == "ACCEPT"
    assert not ({"capability_not_declared", "capability_declaration_missing"} & codes(v))


def test_capability_version_change_requires_redeclaration():
    """The declaration is signed packet content: changing the version without
    re-signing breaks the packet signature; re-signing re-declares."""
    p = packet("k-c14", capability=full_capability(version="1"))
    p["handoff"]["capability"]["version"] = "2"  # no re-sign
    v = check(p)
    assert v["decision"] == "REJECT" and "signature_invalid" in codes(v)
    p = ss.sign_packet(p, ss.load_key(KEYS / "cora.key.json"))
    assert check(p)["decision"] == "ACCEPT"


def test_admission_receipt_reference_is_carried():
    """Feature A cross-reference: an admission receipt id rides the
    declaration (sibling worker owns the receipt format)."""
    p = packet("k-c15", capability=full_capability(admission_receipt="adm-2026-10-12-001"))
    assert check(p)["decision"] == "ACCEPT"


def test_capability_ceiling_merges_across_policy_layers():
    """Top-level and receiver policies intersect like every other ceiling."""
    r = reg()
    r["policy"] = {"capability": {"tools": ["read_repo", "gmail_send"], "env": ["A", "B"]}}
    r["agents"]["caddy"]["policy"]["capability"] = {"tools": ["read_repo"], "env": ["B", "C"]}
    merged = hc.receiver_policy(r, "caddy")["capability"]
    assert merged["tools"] == ["read_repo"] and merged["env"] == ["B"]
    # a declaration inside the merged ceiling passes ...
    p = packet("k-c16", capability=full_capability(tools=["read_repo"], env=["B"]))
    p["handoff"]["planned_actions"] = [{"name": "read_rules", "tool": "read_repo"}]
    p = ss.sign_packet(p, ss.load_key(KEYS / "cora.key.json"))
    assert check(p, registry=r)["decision"] == "ACCEPT"
    # ... and one outside it does not.
    p = packet("k-c17", capability=full_capability(tools=["read_repo", "gmail_send"]))
    v = check(p, registry=r)
    assert v["decision"] == "REJECT" and "capability_exceeds_receiver_policy" in codes(v)


# ---- runtime hook: check_capability_use --------------------------------------
def test_runtime_hook_allows_declared_use():
    d = full_capability()
    assert hc.check_capability_use(d, "env", "OPENAI_API_KEY") is None
    assert hc.check_capability_use(d, "path", "project/a.txt") is None
    assert hc.check_capability_use(d, "tool", "read_repo") is None


def test_runtime_hook_denies_everything_outside():
    d = full_capability()
    assert hc.check_capability_use(d, "env", "AWS_SECRET")["code"] == "capability_not_declared"
    assert hc.check_capability_use(d, "path", "other/a.txt")["code"] == "capability_not_declared"
    assert hc.check_capability_use(d, "tool", "shell_exec")["code"] == "capability_not_declared"
    assert hc.check_capability_use(d, "network")["code"] == "capability_not_declared"
    assert hc.check_capability_use(d, "network")["state"] == "blocked"


def test_runtime_hook_rejects_unsafe_paths_outright():
    """Bug A: traversal/absolute/backslash paths are capability_path_unsafe
    (blocked), not merely 'not declared'."""
    d = full_capability()
    for bad in ["src/../.ssh/id_rsa", "../etc/passwd", "/etc/passwd",
                "src\\..\\secrets", "C:\\Windows\\x", ".."]:
        r = hc.check_capability_use(d, "path", bad)
        assert r["code"] == "capability_path_unsafe", (bad, r)
        assert r["state"] == "blocked"
    # ... while the reviewer's exact repro with a src/** declaration is denied
    d2 = {"version": "1", "paths": ["src/**"]}
    r = hc.check_capability_use(d2, "path", "src/../.ssh/id_rsa")
    assert r["code"] == "capability_path_unsafe"
    assert hc._glob_covers("src", "src/../secrets") is False
    # ... and the honest path still works.
    assert hc.check_capability_use(d2, "path", "src/main.py") is None


def test_traversal_in_planned_action_rejected():
    p = packet("k-c3b", capability=full_capability())
    p["handoff"]["planned_actions"][0]["params"] = {"paths": ["project/../../etc/passwd"]}
    p = ss.sign_packet(p, ss.load_key(KEYS / "cora.key.json"))
    v = check(p)
    assert v["decision"] == "REJECT" and "capability_path_unsafe" in codes(v)


def test_unsafe_declared_path_is_malformed():
    """A signed declaration smuggling a traversal/absolute path is malformed."""
    for bad in ["../etc/**", "/workspace/project/**", "src\\..\\x"]:
        p = packet("k-c12b", capability=full_capability(paths=[bad]))
        v = check(p)
        assert v["decision"] == "REJECT" and v["state"] == "invalid", (bad, v)
        assert "malformed:capability.paths" in codes(v), (bad, codes(v))


def test_runtime_hook_denies_all_without_declaration():
    for kind, value in [("env", "A"), ("path", "w/a"), ("tool", "t"), ("network", None)]:
        r = hc.check_capability_use(None, kind, value)
        assert r["code"] == "capability_not_declared", (kind, r)


def test_runtime_hook_network_declared():
    d = full_capability(network=True)
    assert hc.check_capability_use(d, "network") is None


# ---- team topologies ----------------------------------------------------------
def test_declared_edge_with_valid_packet_accepts():
    """Oct 10 spec C.2: a handoff along a declared edge is accepted as before."""
    p = packet("k-t1", sender_role="em", receiver_role="qa")
    v = check(p, registry=reg_with_topology())
    assert v["decision"] == "ACCEPT", v
    assert v["topology"] == "ship-team"


def test_undeclared_edge_qa_to_ceo_rejected():
    """Oct 10 spec C.1: qa -> ceo with no declared edge is topology_violation."""
    p = packet("k-t2", sender_role="qa", receiver_role="ceo")
    v = check(p, registry=reg_with_topology())
    assert v["decision"] == "REJECT" and v["state"] == "blocked"
    assert "topology_violation" in codes(v)


def test_edges_are_directed():
    r = reg_with_topology(ship_team(edges=[["em", "qa"]]))
    assert check(packet("k-t3", sender_role="em", receiver_role="qa"), registry=r)["decision"] == "ACCEPT"
    v = check(packet("k-t4", sender_role="qa", receiver_role="em"), registry=r)
    assert v["decision"] == "REJECT" and "topology_violation" in codes(v)


def test_roles_without_configured_topology_fail_closed():
    v = check(packet("k-t5", sender_role="em", receiver_role="qa"))  # no topology in policy
    assert v["decision"] == "REJECT" and "topology_violation" in codes(v)


def test_require_topology_without_roles_is_invalid():
    v = check(packet("k-t6"), registry=reg_with_topology(require_topology=True))
    assert v["decision"] == "REJECT" and v["state"] == "invalid"
    assert "topology_declaration_missing" in codes(v)


def test_require_topology_without_named_topology_is_registry_malformed():
    v = check(packet("k-t7", sender_role="em", receiver_role="qa"),
              registry=reg(require_topology=True))  # flag set, no topology named
    assert v["decision"] == "REJECT" and v["state"] == "invalid"
    assert "registry_malformed" in codes(v)


def test_unknown_topology_name_is_registry_malformed():
    r = reg(topology="no-such-team")
    r["topologies"] = {}
    v = check(packet("k-t8", sender_role="em", receiver_role="qa"), registry=r)
    assert v["decision"] == "REJECT" and "registry_malformed" in codes(v)


def test_role_tool_outside_role_declaration_rejected():
    """Oct 10 spec C.3: a role invoking a tool outside its role declaration."""
    p = packet("k-t9", sender_role="em", receiver_role="qa")
    p["handoff"]["planned_actions"][0]["tool"] = "shell_exec"
    p = ss.sign_packet(p, ss.load_key(KEYS / "cora.key.json"))
    v = check(p, registry=reg_with_topology())
    assert v["decision"] == "REJECT" and "capability_not_declared" in codes(v)


def test_topology_change_without_resign_is_rejected():
    """Oct 10 spec C.4: changing the topology requires re-signing."""
    r = reg_with_topology()
    r["topologies"]["ship-team"]["edges"].append(["qa", "ceo"])  # no re-sign
    p = packet("k-t10", sender_role="qa", receiver_role="ceo")
    v = check(p, registry=r)
    assert v["decision"] == "REJECT" and v["state"] == "invalid"
    assert "topology_signature_invalid" in codes(v)


def test_topology_resign_after_change_admits_new_edge():
    r = reg_with_topology()
    topo = r["topologies"]["ship-team"]
    unsigned = {k: v for k, v in topo.items() if k not in ("signed_by", "kid", "sig")}
    unsigned["edges"] = unsigned["edges"] + [["qa", "ceo"]]
    unsigned["version"] = "2026-10-12.2"
    r["topologies"]["ship-team"] = ss.sign_topology(
        "ship-team", unsigned, ss.load_key(KEYS / "rohan.key.json"))
    p = packet("k-t11", sender_role="qa", receiver_role="ceo")
    assert check(p, registry=r)["decision"] == "ACCEPT"


def test_unsigned_topology_rejected():
    r = reg_with_topology({"version": "1", "roles": ["a", "b"], "edges": [["a", "b"]]})
    v = check(packet("k-t12", sender_role="a", receiver_role="b"), registry=r)
    assert v["decision"] == "REJECT" and "topology_signature_missing" in codes(v)


def test_topology_signed_by_non_human_rejected():
    """Topologies must be signed by a founder (a registered human)."""
    topo = {"version": "1", "roles": ["a", "b"], "edges": [["a", "b"]]}
    signed = ss.sign_topology("ship-team", topo, ss.load_key(KEYS / "cora.key.json"))
    r = reg_with_topology(signed)
    v = check(packet("k-t13", sender_role="a", receiver_role="b"), registry=r)
    assert v["decision"] == "REJECT" and "topology_signer_not_founder" in codes(v)


def test_malformed_topology_rejected():
    r = reg_with_topology({"version": "1", "roles": ["a"],
                           "edges": [["a", "ghost"]]})  # edge names an unknown role
    r["topologies"]["ship-team"] = ss.sign_topology(
        "ship-team", r["topologies"]["ship-team"], ss.load_key(KEYS / "rohan.key.json"))
    v = check(packet("k-t14", sender_role="a", receiver_role="a"), registry=r)
    assert v["decision"] == "REJECT" and "topology_malformed" in codes(v)


def test_topology_configured_but_no_roles_stays_backward_compatible():
    """Roles are optional unless require_topology: a packet with no roles
    makes no routing claim, so a configured topology does not reject it."""
    v = check(packet("k-t16"), registry=reg_with_topology())
    assert v["decision"] == "ACCEPT", v
    assert "topology" not in v


def test_topology_and_capability_compose():
    """The packet declaration and the receiver role's capability both narrow."""
    r = reg_with_topology()
    p = packet("k-t15", sender_role="em", receiver_role="qa",
               capability=full_capability(tools=["read_repo"]))  # narrower than qa's role cap
    v = check(p, registry=r)  # planned actions use read_repo + gmail_send
    assert v["decision"] == "REJECT" and "capability_not_declared" in codes(v)


# ---- v2: agent-to-role binding (bug B) ----------------------------------------
def test_spoofed_sender_role_rejected():
    """Bug B: mallory claims the em role to ride the em -> qa edge. The edge
    exists, but mallory is not bound to em in the signed topology."""
    p = packet("k-t20", sender_role="em", receiver_role="qa", from_agent="mallory")
    v = check(p, registry=reg_with_topology())
    assert v["decision"] == "REJECT" and v["state"] == "blocked"
    assert "topology_role_unbound" in codes(v)
    assert "topology_violation" not in codes(v)  # the edge itself is fine


def test_receiver_role_binding_enforced():
    """h.to must be a member of the claimed receiver_role: rebind qa to
    someone else and caddy's qa claim fails."""
    r = reg_with_topology(ship_team(members={"em": ["cora"], "qa": ["mallory"]}))
    p = packet("k-t21", sender_role="em", receiver_role="qa")
    v = check(p, registry=r)
    assert v["decision"] == "REJECT" and "topology_role_unbound" in codes(v)


def test_memberless_topology_fails_closed():
    """A signed topology with no `members` binding cannot verify role claims:
    fail closed, never silently pass."""
    topo = ship_team()
    unsigned = {k: v for k, v in topo.items()
                if k not in ("signed_by", "kid", "sig", "members")}
    r = reg_with_topology(ss.sign_topology(
        "ship-team", unsigned, ss.load_key(KEYS / "rohan.key.json")))
    p = packet("k-t22", sender_role="em", receiver_role="qa")
    v = check(p, registry=r)
    assert v["decision"] == "REJECT" and "topology_role_unbound" in codes(v)


def test_malformed_members_rejected():
    r = reg_with_topology(ship_team(members={"qa": "cora"}))  # not a list
    v = check(packet("k-t23", sender_role="em", receiver_role="qa"), registry=r)
    assert v["decision"] == "REJECT" and v["state"] == "invalid"
    assert "topology_malformed" in codes(v)


def test_members_change_without_resign_rejected():
    """Rebinding a role without re-signing breaks the founder signature."""
    r = reg_with_topology()
    r["topologies"]["ship-team"]["members"]["em"] = ["mallory"]  # no re-sign
    p = packet("k-t24", sender_role="em", receiver_role="qa")
    v = check(p, registry=r)
    assert v["decision"] == "REJECT" and v["state"] == "invalid"
    assert "topology_signature_invalid" in codes(v)


def test_rebound_role_admits_new_member():
    """A founder re-sign after rebinding em to mallory admits mallory's claim."""
    topo = ship_team()
    unsigned = {k: v for k, v in topo.items() if k not in ("signed_by", "kid", "sig")}
    unsigned["members"] = dict(unsigned["members"], em=["mallory"])
    unsigned["version"] = "2026-10-12.2"
    r = reg_with_topology(ss.sign_topology(
        "ship-team", unsigned, ss.load_key(KEYS / "rohan.key.json")))
    p = packet("k-t25", sender_role="em", receiver_role="qa", from_agent="mallory")
    assert check(p, registry=r)["decision"] == "ACCEPT"
