"""ATTACK B (bug B): sender-asserted roles dodge topology enforcement.

Story: `cora` is really a QA engineer, but the packet claims sender_role="em"
because the em -> qa edge exists in the signed ship-team topology. Roles are
sender-asserted labels in v1, so the edge check alone passes and the handoff
is ACCEPTed even though cora is not an EM.

On v1 this prints ACCEPT (the bug). On v2 the signed topology binds agents to
roles via `members: {role: [agent ids]}` and the gate checks h.from / h.to
against the bound roles, so this packet is rejected (topology_role_unbound).
"""
import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import handoff_check as hc
import synthe_sign as ss

V3 = ROOT / "examples" / "v03"
KEYS = V3 / "test-keys"
FAR = "2999-01-01T00:00:00Z"

def ship_team(**kw):
    """Oct 10 spec's example topology, signed by founder rohan. v2 adds the
    members binding; v1 topologies carry no binding at all."""
    topo = {"version": "2026-10-12.1",
            "roles": ["ceo", "designer", "em", "qa", "release"],
            "edges": [["ceo", "designer"], ["designer", "em"], ["em", "qa"],
                      ["qa", "release"], ["qa", "em"]],
            "role_capabilities": {"qa": {"tools": ["read_repo", "run_tests", "gmail_send"]}},
            # v2: which agents may claim which role. cora is QA, not an EM.
            "members": {"ceo": ["rohan"], "designer": ["artem"], "em": ["dylan"],
                        "qa": ["cora", "bob"], "release": ["sam"]}}
    topo.update(kw)
    return ss.sign_topology("ship-team", topo, ss.load_key(KEYS / "rohan.key.json"))

def main():
    r = json.loads((V3 / "registry.json").read_text())
    r["agents"]["caddy"]["policy"].update(topology="ship-team")
    r["topologies"] = {"ship-team": ship_team()}

    p = json.loads((V3 / "packets" / "valid-signed.json").read_text())
    h = p["handoff"]
    h["idempotency_key"], h["id"] = "k-atk-b", "h-k-atk-b"
    h["authority"]["approvals"] = []
    # cora (really QA) claims the EM role to ride the em -> qa edge.
    h["sender_role"], h["receiver_role"] = "em", "qa"
    ss.approve_packet(p, ss.load_key(KEYS / "rohan.key.json"), "send_email", FAR)
    p = ss.sign_packet(p, ss.load_key(KEYS / "cora.key.json"))

    v = hc.check(copy.deepcopy(p), registry=r, ledger_path=None,
                 workspace=V3 / "workspace", dry_run=True)
    codes = sorted({x["code"] for x in v.get("reasons", [])})
    print(f"spoofed-role packet (from=cora, sender_role=em) -> {v['decision']} {codes}")
    if v["decision"] == "REJECT":
        for x in v["reasons"]:
            print("  -", x["code"], "::", x["message"][:160])

if __name__ == "__main__":
    main()
