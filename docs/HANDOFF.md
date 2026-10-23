# Handoff: "install it and forget it" Synthe

Work in progress on branch `claude/modest-noether-9o09k1`. This note is for whoever picks it up next
(a local Claude Code session or a person). Delete it once the work is merged.

## The goal (founder)

Install Synthe, then just work with agents. You hear from Synthe only when it stops or flags
something, and it tells you why that mattered. Defaults are as autonomous as possible: no caps on
lanes or self-issued tasks unless someone asks for them.

## Done and merged on this branch

| Part | What | Where |
|---|---|---|
| Notifications | `synthe-notify watch / digest / test`: verifies the receipt chain, notifies only on stops and things waiting for a person, plain-English "what this stopped and why it matters" for every reason code, weekly digest | `src/synthe_notify.py`, `docs/NOTIFY.md`, `tests/test_notify.py` |
| One-command lanes | `synthe-task grant / grants / revoke-grant`; setup ends with "How hands-off?" (the autonomous lane is the default answer) | `src/synthe_grant.py`, `src/synthe_init.py` (`lane-offer`), `tests/test_task_grant.py` |
| Risk-aware lanes | grant field `auto_approve` (default `["routine","review"]`); high-risk pushes and pushes outside the lane's paths are staged for a person (`risk_escalated`, `outside_lane_paths`); limits optional (omit `max_uses` / `expires_at` = none) | `src/synthe_risk.py`, `src/synthe_lane_templates.py`, `src/synthe_commit.py`, `tests/test_risk*.py` |
| Self-issued tasks: design | how the broker issues tasks inside a lane so the person stops signing every task | `docs/design/SELF_ISSUED_TASKS.md` |

Founder decisions already made: no default limits anywhere; dependency manifests, lockfiles,
Dockerfiles and build scripts go out without asking under the default lane (review tier), and the
weekly digest lists them afterwards; only high-risk pushes (CI workflows, secret-like files, large
deletions or diffs) and out-of-lane pushes ask the person.

## Known failing on this branch right now (fix in the integration task)

1. `tests/test_task_grant.py::test_a_push_on_the_lanes_branch_but_outside_its_paths_is_refused_not_asked_about`:
   behaviour changed on purpose; out-of-lane pushes now ask the person. Update the test and the
   "refused, not asked about" wording.
2. `tests/test_notify.py::test_every_reason_code_has_a_message`: add messages for `risk_escalated`,
   `outside_lane_paths`, `risk_rules_invalid`.

Environment-only failures in the cloud sandbox (it runs as root, package not installed): 19 in
`tests/test_install_entrypoint.py`, 4 in `tests/test_plugin_mcp_startup.py`. They should pass on a Mac.
Baseline before this work: 1648 passed, those 23 failed.

## Still to do

### A. Integration (smaller; do first)
- Fix the two tests above. Notifier texts for escalations, built from the receipt's `risk` /
  `lane_scope` objects ("Needs you: this push changes a CI workflow (.github/workflows/ci.yml)").
- `synthe-task grant`: send `auto_approve` (default from the broker's `lane_template_draft` op,
  `--auto-approve` to override), get lineage via `lane_template_draft {"receiver", "auto_approve"}`,
  and OMIT `max_uses` / `expires_at` when no `--uses` / `--until` (remove the 10000 / 9999-01-01
  encoding). Summary text lists what still asks the person, derived from the broker's real high-tier
  rules, and must not claim dependency changes ask.
- `synthe-approver grant`: include `auto_approve` and real lineage.
- Approval card (`src/synthe_approve.py`): say "outside your lane: N files" and "your lane sent this to
  you because: …".
- `synthe-notify install-agent / uninstall-agent` (macOS LaunchAgent, Linux `systemd --user`); setup
  offers to turn notifications on (in the person's account, never the agent's); install script lists
  `synthe-notify`.
- Digest: list review-tier pushes that went out under a lane ("3 dependency changes went out").
- Quickstart rewritten around install → choose the autonomous lane + notifications → work → only hear
  from Synthe when it matters.

### B. Self-issued tasks (larger, security-critical)
Implement `docs/design/SELF_ISSUED_TASKS.md` with these overrides: no default limits (max tasks,
open tasks, rate all optional); revoking or expiring the grant kills unlanded self-issued tasks;
default purpose on a plain `git push` is the tip commit's subject (`-o synthe.purpose=` overrides);
self-issue requires the grant not to auto-approve "high" (or to have a delegate); separate
`synthe-issuer` key held by the broker's user; ship Phase 0 (`trusted_senders`, `sender_not_trusted`);
receipts carry `task_origin` so the digest can list self-issued work. Update SPEC.md, THREAT_MODEL.md,
docs/COMMIT.md, docs/REDTEAM.md, scripts/redteam_live.py, with end-to-end and mutation tests.
After it lands, `synthe-task grant` needs a `--self-issue` flag (on for the setup lane).

### C. Then
- Full suite on a Mac (`python3 -m pytest -q`), then the live red team (`docs/REDTEAM.md`) on a real
  ENFORCED install, adding rows for lanes, risk escalation and self-issue.
- Open a pull request to `main` when green.
