# Registry genesis key: runbook

The agent registry (`registry.json`) says who exists: which agents and approvers there are, their
public keys, and each agent's policy. Whoever can edit it decides who may approve. This runbook covers
signing it with an operator key and pinning that key so verifiers refuse any registry the operator
didn't sign.

Every command and message below was checked against `src/synthe_sign.py`, `src/handoff_check.py` and
`src/synthe_crypto.py`, and run end to end with the CLI.

## Why a signature means nothing until a key is pinned

A signed registry carries a `signature` block: a chain of operator keys starting at a **genesis**
key, plus a signature over the registry body by the chain's current key. The genesis entry signs
itself, so anyone can make one. A signature that verifies only proves that *somebody* signed the
file. It doesn't prove the signer was your operator.

So the checker only enforces signatures once you tell it which genesis key to trust:

| Pin configured? | What the checker does |
|---|---|
| No | Loads the registry **unverified**, signed or not. `synthe-check --registry …` prints the warning below. The broker, `synthe-mcp` and `synthe-a2a` load it the same way, with no warning. |
| No, with `synthe-check --require-signed-registry` | Refuses: `registry_signature_invalid` ("a signed registry is required but no genesis key is pinned…"). |
| Yes | The registry **must** be signed, its chain must lead back to the pinned genesis key, and the body signature must verify under the chain's current key. Anything else is `REJECT` with `registry_signature_invalid`. |

The warning you see until you pin:

```
WARNING: no registry genesis key is pinned, so the agent registry is NOT verified: whoever can edit it decides who exists. Sign it with `synthe-sign sign-registry` and pin the key (--registry-genesis-key or SYNTHE_REGISTRY_GENESIS_KEY).
```

## Who holds the key

The operator key belongs to one named person: whoever decides who may approve. In a one-person
install that's you, the approver. On a team it's the person who owns the registry. Write the name
down where your team keeps ownership records.

It must never be on:
- the agent's account;
- the broker's `_synthe` account;
- a CI runner or in a CI secret. CI only needs the public pin.

Keep it offline and encrypted: generate it with `--encrypt`, and store the file on removable media
or in a password manager, not on the machine the agent runs on. Keep one backup in a second place
that you control. Lose every copy and you can't sign registry changes, so you'd have to start a new
chain and re-pin everywhere (see "If a key is lost or exposed").

## 1. Generate the operator key

```bash
synthe-sign keygen --agent registry-operator --kid op-1 --out op-1.key.json --encrypt
```

- `--agent` is required. Here it is only a label stored in the key file. The operator is not an
  agent: **don't** add this key to the registry, even though `keygen` suggests pasting it under
  `agents.registry-operator.keys`. That hint is for agent keys.
- `--encrypt` asks for a passphrase twice (at least 12 characters) and seals the key with scrypt.
  An encrypted key unlocks only at a terminal: the CLI refuses a passphrase piped in by a process.
- Without `--kid` the key id would be `registry-operator-1`. Use `op-1` so the chain reads cleanly.

What you should see:

```
New passphrase (at least 12 characters):
Type it again:
{
  "kid": "op-1",
  "alg": "Ed25519",
  "public_key": "TC4jLkrMq2aGYDfqQva1-uvdVWNQUkeSLdohcyobfgM"
}
# private key written to op-1.key.json (encrypted with your passphrase); paste the object above under agents.registry-operator.keys
```

(Your public key will differ.) The file is written `chmod 600`. `keygen` refuses to overwrite an
existing file unless you pass `--force`.

## 2. Sign the registry

```bash
synthe-sign sign-registry --registry registry.json --key op-1.key.json
```

It asks for the key's passphrase, then signs the file **in place** (`--out FILE` writes elsewhere).
On an unsigned registry this creates the genesis chain:

```
Passphrase for registry-operator's key op-1:
signed registry with new operator key 'op-1' (genesis chain)
  public key: TC4jLkrMq2aGYDfqQva1-uvdVWNQUkeSLdohcyobfgM
  Distribute this public key to verifiers out of band.
```

That public key is your **pin**.

### After you edit a signed registry

Any edit (adding an approver key, changing a policy) breaks the body signature. Re-sign with the
chain's current key. Plain `sign-registry` refuses, because the old body signature no longer matches:

```
refusing to sign: current registry signature invalid: registry body signature does not verify under the current operator key
  (If you edited the body legitimately, re-run with --force.)
```

If the edit was yours, re-run it with `--force`:

```bash
synthe-sign sign-registry --registry registry.json --key op-1.key.json --force
```

```
re-signed registry with operator key 'op-1' (chain length 1 preserved) --force: prior body signature not verified
```

`--force` skips only the stale body signature. The rotation chain is still verified, and the key
must be the chain's current key. Read the diff of the registry before you use `--force`: it signs
whatever is in the file.

### A registry already signed by someone else

`sign-registry` won't re-sign a registry whose chain belongs to another key (for example the
examples in `examples/`, signed by a throwaway key):

```
sign-registry failed: re-signing key is not the registry's current operator key
```

To start your own chain, delete the top-level `"signature"` block and sign again. That is a new
genesis: every verifier needs the new pin.

## 3. Pin the genesis key

The pin is either the genesis public key (base64url, as printed above) or the 64-character hex
SHA-256 fingerprint of its 32 raw bytes. Both work. To get the fingerprint:

```bash
python3 -c 'import base64,hashlib,sys; k=sys.argv[1]; print(hashlib.sha256(base64.urlsafe_b64decode(k+"="*(-len(k)%4))).hexdigest())' TC4jLkrMq2aGYDfqQva1-uvdVWNQUkeSLdohcyobfgM
```

The checker reads the pin from these places, first match wins:

1. `--registry-genesis-key VALUE` (only `synthe-check` has this flag). Write it as
   `--registry-genesis-key=VALUE`: a base64url key can start with `-`.
2. The `SYNTHE_REGISTRY_GENESIS_KEY` environment variable.
3. A `registry-genesis.key` file **in the same directory as the `handoff_check.py` that is
   running**. Lines starting with `#` and blank lines are ignored, so you can annotate it. Nothing
   ships one.

To find that directory for an install:

```bash
~/synthe-venv/bin/python -c 'import handoff_check, os; print(os.path.dirname(handoff_check.__file__))'
```

Check it:

```bash
SYNTHE_REGISTRY_GENESIS_KEY=TC4jLkrMq2aGYDfqQva1-uvdVWNQUkeSLdohcyobfgM \
  synthe-check handoff.json --registry registry.json --dry-run
```

A good registry gives the packet's normal verdict, with no warning. A registry that someone edited
without re-signing gives:

```
"decision": "REJECT",
...
"code": "registry_signature_invalid",
"message": "registry signature rejected: registry body signature does not verify under the current operator key"
```

A registry signed by a different genesis key is rejected with "genesis operator key does not match
the pinned genesis key … this registry was signed by someone else".

### Where to pin

- **`synthe-check` on your machine:** the env var in your shell profile, or the
  `registry-genesis.key` file next to the venv's `handoff_check.py`.
- **The GitHub Action:** the Action has no pin input, and its checker lives in the Action's own
  folder, so use the env var. Set it at job level so the Action's steps inherit it:

  ```yaml
  jobs:
    handoff:
      runs-on: ubuntu-latest
      env:
        SYNTHE_REGISTRY_GENESIS_KEY: ${{ vars.SYNTHE_REGISTRY_GENESIS_KEY }}
  ```

  Keep the pin somewhere the people who can edit the registry file can't also change it.
  Otherwise one person can change who exists and re-pin. This path follows the code (`run_check.sh`
  runs the vendored checker, which reads the env var). It hasn't been run on a hosted runner yet.
- **The macOS broker: not supported yet.** The broker runs the checker from `/Library/Synthe/src`,
  so a `registry-genesis.key` there would take effect. But setup and `deploy/macos/upgrade.sh`
  write the broker's own entry into `/var/db/synthe/registry.json` *after* you'd have signed it
  (`synthe-init apply-config` / `apply-registry`). That edit breaks the signature, and with a pin
  in place the broker would then refuse every registry load, so it would refuse every push. Leave
  the broker unpinned until setup signs as part of the install. Until then the broker's registry is
  protected by file ownership (`_synthe`, mode 600), not by a signature.

## 4. Rotate the operator key

Rotate for a routine handover, for example when the key holder changes. The current key attests the
new key, which extends the chain, and the new key re-signs the body.

```bash
synthe-sign keygen --agent registry-operator --kid op-2 --out op-2.key.json --encrypt
synthe-sign rotate-registry-key --registry registry.json --old-key op-1.key.json --new-key op-2.key.json
```

It asks for each key's passphrase, verifies the current chain and body signature first, and updates
the file in place (`--out FILE` writes elsewhere; `--new-kid` overrides the new key id):

```
rotated registry operator key to 'op-2' (chain length 2; supersedes 'op-1')
  seq 0: 'op-1' TC4jLkrMq2Y...
  seq 1: 'op-2' TQmAaWnPPf8...
```

What changes and what doesn't:

- **Verifiers keep the same pin.** The pin is the genesis key, and the chain links the new key back
  to it. A pinned checker accepts the rotated registry with no change on its side.
- From now on, re-sign edits with `op-2.key.json`. The old key is refused ("re-signing key is not
  the registry's current operator key").
- **Rotation doesn't revoke the old key.** The pin trusts the genesis key, so anyone holding
  `op-1`'s private key can still build a different chain from it that a pinned checker accepts.
  After the rotated registry is deployed everywhere, destroy every copy of the old private key.
- Don't confuse this with `synthe-sign rotate-operator`, which rotates the *revocation* operator
  (`docs/KEY_REVOCATION.md`), a separate key.

### Announcing a rotation

Synthe has no built-in announcement, so do it where your verifiers already look:

1. Commit the rotated `registry.json` in its own change. Name the new kid, the chain length, and
   the person who now holds the key.
2. Paste the `rotate-registry-key` output into that change's description, so anyone can compare the
   `seq` lines with the file.
3. Say plainly that **the pin does not change**. If someone is asked to change their pin during a
   routine rotation, something is wrong.
4. Record the date the old key was destroyed.

## If a key is lost or exposed

Rotation can't fix this. If any private key in the chain was exposed, an attacker can fork the chain
from it. If every copy is lost, you can't sign at all. Either way, start a new chain:

1. Generate a new key (step 1).
2. Delete the `"signature"` block from the registry, check the body is what you expect, and sign it
   (step 2). That creates a new genesis.
3. Replace the pin everywhere it is set (env vars, `registry-genesis.key` files, CI variables).
   Until a verifier has the new pin, it rejects the new registry. That's the intended fail-closed
   behavior.
4. Send the new pin over a channel separate from where the registry lives. Read the fingerprint
   aloud, or post it from a different account. Ask each verifier to confirm the fingerprint, not
   just paste a value.
