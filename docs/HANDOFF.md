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

## Test status

The integration merge (escalation notifications, risk-tier grants without encoded limits, approval
card wording) fixed the two earlier failures: lanes, risk, notify, approve and approver tests pass
(338). The full suite has not been re-run since; run it first.

Environment-only failures in the cloud sandbox (it runs as root, package not installed): 19 in
`tests/test_install_entrypoint.py`, 4 in `tests/test_plugin_mcp_startup.py`. They should pass on a Mac.
Baseline before this work: 1648 passed, those 23 failed.

## Still to do

### A. Integration (items 1–4 DONE and merged; finish 5–7)
- DONE: escalation notifications, `synthe-task grant` with `auto_approve` and omitted limits,
  `synthe-approver grant`, approval card wording, digest lists review-tier pushes.
- `synthe-notify install-agent / uninstall-agent` (macOS LaunchAgent, Linux `systemd --user`); setup
  offers to turn notifications on (in the person's account, never the agent's); install script lists
  `synthe-notify`.
- Quickstart rewritten around install → choose the autonomous lane + notifications → work → only hear
  from Synthe when it matters.

### B. Self-issued tasks (larger, security-critical; about half written)
A previous session wrote most of the code but no new tests and no docs. It is saved as
`docs/handoff/self-issue-wip.patch` (one commit, based on f1fe05c; it applies cleanly to this branch
with `git am -3 docs/handoff/self-issue-wip.patch`). Written: checker (new signing domain
`synthe/handoff-signature/self-issued/v1`, `trusted_senders`, the `self_issue_*` checks), grant
field `self_issue` with optional limits, broker `issue_task` op with `task_issue` receipts and
`task_origin` on later receipts, revoke/expiry kill unlanded tasks, issuer key in setup,
git-remote-synthe issuing on a plain push. Known breakages in the patch (4 tests):
`test_git_push_proposal.py::test_a_push_with_no_task_for_the_branch_is_refused_and_says_what_to_do`
and `::test_an_expired_task_is_not_used` (map `self_issue_not_granted` back to `no_task_for_branch`
with a lane hint in git-remote-synthe), and two in `test_task_grant.py` that compare the
`lane_templates` config exactly (it now carries `self_issue`). Still to write: `tests/test_self_issue.py`
(end to end), `tests/test_self_issue_mutations.py`, SPEC.md v0.7, THREAT_MODEL.md, docs/COMMIT.md,
docs/REDTEAM.md, `schema/handoff.schema.json` (`issued_under_grant`; `additionalProperties: false`
rejects it today), `scripts/redteam_live.py` battery, notifier support for `task_issue_refused` and the
`self_issue_*` codes, `--self-issue` on `synthe-task grant`. Re-copy `src/handoff_check.py` and
`src/synthe_crypto.py` into `github-action/checker/` after checker changes. Decision noted: for
self-issued tasks an out-of-lane push is refused (`path_outside_scope`), not escalated, because the
task's paths sit inside the grant's; only human-signed tasks escalate with `outside_lane_paths`.

The full brief: implement `docs/design/SELF_ISSUED_TASKS.md` with these overrides: no default limits (max tasks,
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
