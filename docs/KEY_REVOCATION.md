# Key revocation

A leaked key used to stay valid until someone rotated its `kid` by hand. Now
the registry carries a revocation list, and every signature verification
consults it: a packet or approval signed with a revoked key fails closed,
even when the signature itself is valid.

## The revocation section

```json
"revocation": {
  "operator": {"agent": "ops", "kid": "ops-1"},
  "past_operators": [
    {"agent": "ops", "kid": "ops-0", "public_key": "<base64url>",
     "retired_at": "2026-10-13T00:00:00+00:00", "reason": "routine rotation"}
  ],
  "revoked_kids": [
    {"v": 1, "agent": "worker", "kid": "worker-3",
     "revoked_at": "2026-10-12T21:30:00+00:00",
     "reason": "key leaked in CI logs",
     "operator_kid": "ops-1", "sig": "<base64url>"}
  ]
}
```

- Revocation is scoped to **(agent, kid)**, not to the kid string alone.
  Kids are only unique per agent: revoking `worker/k1` never affects
  `boss/k1`, even though the kid string is identical.
- `operator` designates the one key allowed to sign revocations: an ordinary
  registered Ed25519 agent key. Keep this key offline or passphrase-encrypted;
  whoever holds it can revoke any key. A record must be signed by the
  *designated* kid: a signature from some other key of the same operator
  agent does not authenticate.
- Each record in `revoked_kids` is signed by the operator over its exact
  fields (domain `synthe/key-revocation/v1`), so revocations can't be forged.
  Records that fail authentication are ignored for enforcement — a forged
  entry can't revoke anyone and can't break verification — but they are
  reported by `synthe-sign revocations` and in the `verify` report, so the
  operator sees that someone wrote them.
- `past_operators` keeps retired operator public keys. When the operator key
  is rotated, the old public key is retired here (verify-only), so records
  it signed keep authenticating: a routine rotation must never un-revoke
  anything. A record signed by a retired key only authenticates when its
  `revoked_at` is not later than the key's `retired_at` — retired keys can
  never issue *new* revocations. Retired keys are never used for any other
  verification.
- **Rollback stays undetected by this item.** Deleting a revocation record
  from the registry file is not detected here: it stays undetected until the
  registry itself is signed and pinned per the signed-registry item. The
  registry remains operator-controlled; a writer who can delete agent keys
  outright can do worse than delete a revocation.

## Revoking a key

```bash
synthe-sign revoke-kid --registry registry.json \
  --agent worker --kid worker-3 \
  --operator-key ops.key.json \
  --reason "key leaked in CI logs"
```

On first use the operator key designates itself as the revocation operator.
After that, only that key's file can issue revocations. The command refuses
when:

- the key file isn't the designated operator's,
- the operator key is itself revoked (rotate it with `rotate-operator`,
  then revoke),
- the kid isn't registered for the agent — a typo'd kid must never silently
  leave the leaked key valid while the operator believes it revoked.

Revoking is idempotent: revoking an already-revoked key is a no-op.

```bash
synthe-sign revocations --registry registry.json   # audit: operator, revocations, problems
```

## Rotating the operator key

```bash
synthe-sign rotate-operator --registry registry.json \
  --operator-key ops-old.key.json \
  --new-operator-key ops-new.key.json \
  --reason "routine rotation"
```

The old public key is retired into `revocation.past_operators` (verify-only)
and the new key is designated. From then on the new key issues revocations
and the old one can't — but every revocation the old key signed keeps
enforcing, because the old records still authenticate against the retired
key. The new key must already be registered as an Ed25519 key and must not
be revoked. Retiring without keeping the old public key (e.g. hand-editing
the registry) silently un-revokes everything it signed; `revocations`
reports that as a problem, but the enforcement is gone — use the ceremony.

## What verification does

- `handoff_check.py`: a packet signed with a revoked (agent, kid) fails with
  `signature_key_revoked`; a revoked approval key fails with
  `approval_key_revoked`. Both are `invalid` verdicts (exit 2), fail-closed.
- `synthe-sign verify` reports `REVOKED` for either and exits 2.
- Broker receipt verification (`synthe_commit.py`) rejects receipts from a
  revoked broker key.
- Revoked keys are excluded from `usable_keys`/`usable_approval_keys`, so
  after you revoke the old key and register the new one, signatures don't
  need to name a kid to avoid the retired key — the retired key simply isn't
  usable anymore.

## Human approver keys

Revocation is the fast path when a key leaks, but human approver keys deserve
stronger custody than agent keys, because a human's signature is the last
human in the loop:

- **Today: the OS keychain.** Keep the human's private key in the platform
  credential store (macOS Keychain, and the Secure Enclave via Touch ID —
  see `docs/TOUCHID.md`, which registers a non-exportable ES256 approval key)
  or in a passphrase-encrypted key file (`synthe-sign keygen --encrypt`,
  `synthe-sign protect`; scrypt + AES-256-GCM, unlocked only by a person at a
  terminal). Never a plaintext file: `synthe-approve` and `synthe-init`
  refuse plaintext approver keys, and `synthe-sign approve` warns loudly.
  A plaintext approver key is readable by anything running as you — an agent
  included — which can then approve its own work.
- **Later: passkeys / WebAuthn.** The natural end state is a platform
  authenticator (passkey) as the approval key: phishing-resistant,
  hardware-backed, with user verification built in. Synthe's approval bytes
  bind the action to its handoff, idempotency key, and pinned params; a
  WebAuthn ceremony can carry exactly those bytes as the challenge, so the
  human gesture signs precisely what the checker verifies. That integration
  isn't built yet — custody today is keychain / Secure Enclave /
  passphrase-encrypted files, with revocation as the backstop when any of
  them leaks.
