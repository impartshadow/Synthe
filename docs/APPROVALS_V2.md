# Approvals bind the budget (approval signature v2)

## What changed

An approval signature used to cover `{action, approver, expires_at,
idempotency_key, from, to}` plus optional v0.4 `params` -- but not the budget.
An approver signing "deploy" could not cap it at $50 vs $5000; only the
receiver-policy ceiling limited magnitude.

Approvals are signed under a new domain,
`synthe/approval-signature/v2`, and every approval **pins the budget**
(`tokens`/`usd`/`minutes`) and the approved action's cost estimates
(`est_tokens`/`est_usd`/`est_minutes`) as signed ceilings: afterwards the
packet's budget and the action's estimates may only come down, never up.

Two further rules:

1. **Signing is refused without a budget.** `approve_packet()` /
   `detached_approval()` / `synthe-sign approve` fail with a clear message
   (naming `--budget`) unless a complete budget can be bound. The pin is the
   *effective* budget: per dimension, the approver's explicit budget first,
   then the packet's explicit `authority.budget`, then the receiver policy's
   `defaults.budget` (the same merge the checker applies).
2. **A v2 approval carrying no budget pin is rejected outright**
   (`approval_budget_missing`). It caps nothing, so it authorizes nothing --
   it is never treated as an unlimited approval.

## (a) The v1 -> v2 signature break

**Live v1 approvals in broker stores will stop verifying.** Any approval
signed under `synthe/approval-signature/v1` (before v2) is rejected
with `approval_version_unsupported`: it is never re-verified under the new
semantics, and it never passes as a confusing `approval_signature_invalid`.

Concretely, this affects:

- `approvals.jsonl` broker stores holding detached approvals signed before
  the cutover -- staged proposals waiting on those approvals will stay
  staged (`approval_version_unsupported`, then `approval_missing`) until
  re-approved.
- Detached approval files (`approval.json`) created with the old
  `synthe-sign approve --detached`: they cannot be submitted after the
  cutover.
- Embedded approvals in already-signed packets: those packets were signed
  before the cutover, so they predate v2 everywhere; re-issuing the packet
  re-signs it and needs a fresh v2 approval anyway.

Nothing in-repo migrates stored broker state. The break is deliberate and
fail-closed: a v1 approval cannot express a budget ceiling, so honoring it
would silently grant uncapped spend.

## (b) Migration guide: re-issuing approvals under v2

Do this **after** upgrading the checker and signer, in this order:

1. **Inventory outstanding approvals.**
   ```bash
   # staged proposals still waiting on an approval
   python3 src/synthe_client.py --broker <url> staged
   # broker store on disk: detached approvals not yet consumed
   grep -c '"budget"' <broker-state-dir>/approvals.jsonl   # lines WITH a pin
   ```
   Every staged proposal whose approval predates the cutover needs a fresh
   approval; there is no in-place upgrade path for a signature. (An approval
   line in `approvals.jsonl` without a `budget` object is a v1 approval.)

2. **Re-issue each approval.** For a packet file:
   ```bash
   python3 src/synthe_sign.py approve handoff.json \
     --key keys/<approver>.key.json \
     --action <action> \
     --budget '{"tokens": 1000, "usd": 5, "minutes": 30}' \
     --out handoff.approved.json
   ```
   - `--budget` is required when the packet names no `authority.budget`
     (the common case for minimal packets that rely on receiver defaults).
     Name the ceiling you actually authorize; the approval caps the spend at
     exactly this -- the packet's budget may only come down afterwards.
   - If the packet *does* name `authority.budget`, `--budget` is optional
     and overrides per dimension (a tighter cap than the packet states).
   - For detached approvals (broker-mediated effects), add `--detached
     --out approval.json` and submit it as before:
     ```bash
     python3 src/synthe_client.py --broker <url> approve-submit approval.json
     ```
   - From the terminal approval card (`synthe-approve`), no action is
     needed: the broker now supplies the effective budget and the card pins
     it automatically.

3. **Verify the cutover.**
   ```bash
   # a re-issued packet verifies cleanly under v2
   python3 src/synthe_sign.py verify handoff.approved.json --registry registry.json
   # the checker accepts it (dry run: no ledger claim)
   python3 src/handoff_check.py handoff.approved.json \
     --registry registry.json --workspace . --ledger /tmp/probe-ledger.json
   # old v1 approvals fail closed with the explicit version code, never silently
   python3 src/synthe_sign.py verify old-handoff.json --registry registry.json
   #   -> approvals[].status == "UNSUPPORTED_VERSION"
   ```
   Then confirm no staged proposal is still waiting on a v1 approval
   (step 1's `staged` list should be empty of `approval_version_unsupported`
   receipts), and confirm `approvals.jsonl` contains no approval without a
   `budget` object.

4. **Roll back plan.** If the cutover must be reverted, redeploy the
   previous signer/checker; v2 approvals will then fail as
   `approval_signature_invalid` (unknown domain) and the old v1 approvals
   verify again. Keep the re-issued v2 approvals: they verify again once v2
   is re-deployed.
