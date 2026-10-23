# Handoff Contract Check — GitHub Action

> **Status (2026-09-30):** Option 2 hardening is included on main and is
> **proven by a local simulation only** (`tests/test_two_runner.py`,
> `simulate_two_runners.py` in this folder): the simulation models two
> isolated runner workspaces plus an ordered cache hand-off. It is **not**
> a run on real GitHub infrastructure. One real two-runner GitHub run (the
> manual "Synthe two-runner verification" workflow) is still required
> before the cross-run exactly-one claim can be stated without the
> "simulated" qualifier (see "What is proven, what is not"). The public
> repo's README/AGENTS keep the v0.2 claim until that run passes; the
> checker CLI and its verdict states are unchanged.

A composite GitHub Action that runs the **Handoff Contract** validator on
an agent-to-agent handoff packet and fails the CI step when the handoff is
rejected. Use it to gate agent work: an agent that wants another agent
(or a human) to pick up its work must present a valid handoff packet, and
the claim must be completed after the effect is real, or the packet
cannot be replayed as if nothing happened.

The checker is a single stdlib-only Python file (vendored under
`checker/`), so the action needs **no network access and no
dependencies** — just `python3`, which is preinstalled on GitHub-hosted
runners.

## What it checks

Given a handoff packet (see `../SPEC.md` for the format), the validator
confirms, before the receiver starts work:

- all required fields are present and the schema version is supported;
- the sender and receiver are canonical agent ids in the registry (no
  aliases, no unknown agents);
- the handoff has not expired;
- every planned action uses an allowed tool, is not forbidden by scope,
  has any required approval on file (and unexpired), and fits the budget;
- every referenced artifact exists in the workspace and matches its
  recorded SHA-256 hash (no stale files);
- all required evidence is attached, and evidence that must be verbatim
  (quotes, code, legal text) is flagged as verbatim, not paraphrased;
- duplicate protection via the idempotency ledger: the handoff's key has
  not already been claimed or executed (see "Duplicate protection &
  cross-run safety" below).

The checker exits `0` on ACCEPT and `2` on REJECT (printing the failure
state — `invalid`, `incomplete`, `stale`, `conflicting`, `blocked`,
`duplicate`, `unknown` — and reason codes); the Action's entrypoint
normalizes a rejection to step exit `1` with the reasons shown in the
step log and as a workflow error annotation.

## The two phases: claim, then complete

A handoff claim is a two-step state machine, not a single "seen it" flag,
and each step is a separate invocation of this Action:

1. **Claim** (`phase: claim`, the default) — run *before* the receiving
   agent acts. The checker validates the packet and, on ACCEPT, records
   the idempotency key as `RESERVED` in the ledger. This is only a
   claim: the effect has not happened yet.
2. **Complete** (`phase: complete`) — run *after* the receiving agent's
   effect is real. The Action restores the ledger again, flips the key
   from `RESERVED` to `COMPLETED`, and saves the ledger back.

Re-presenting a `COMPLETED` key is rejected as `duplicate`
(terminal: that effect already happened). Re-presenting a `RESERVED`
key within 24 hours (`--reserve-ttl-hours` on the checker) is also
`duplicate` ("claimed by handoff X; reconcile before redispatch"). A
`RESERVED` claim older than the TTL yields the failure state `unknown`:
the receiver may have crashed before *or after* the effect, so reconcile
against the receiver's effect receipt before redispatching. Completing
an already-`COMPLETED` key is an idempotent no-op success.

Why two invocations instead of one? Because persistence has to wrap each
transition. In v0.2 the Action saved its ledger cache *before* the
receiver ran, so a `--complete` performed later in the job flipped only
a throwaway workspace file and the `COMPLETED` state was never persisted
by the Action. Now each phase restores → mutates → re-saves.

## Duplicate protection & cross-run safety

Duplicate detection needs memory: which idempotency keys have already
been claimed. That memory lives in a JSON **ledger**. GitHub-hosted
runners are **ephemeral** — each job gets a fresh machine and the
workspace is discarded — so when you don't pass the `ledger` input, the
Action manages one at `.synthe/ledger.json`:

1. `actions/cache/restore` restores it before the phase (key
   `synthe-ledger-<owner>/<repo>`, prefix fallback to the newest
   snapshot).
2. The checker validates against it and records the transition in it.
3. `actions/cache/save` writes it back under a per-run key, **even if
   the step failed** (`if: always()`), so a rejected claim attempt is
   persisted state too.

That gives each run the previous run's ledger ("cache chaining"). It is
**not sufficient on its own**: cache entries are immutable snapshots,
not an atomic compare-and-set. Two workflow runs that start at the same
time restore the *same* snapshot, both see the key as unclaimed, and
both ACCEPT — the checker's file lock cannot help, because the runners
share no filesystem. An independent reviewer demonstrated exactly this
against v0.2. The missing piece is ordering: your workflow must
serialize the runs that share a ledger. GitHub provides that as a
workflow-level `concurrency` group.

### Ledger integrity: sealed chain + out-of-cache anchor (v0.6)

> **`GITHUB_TOKEN` can't write repository variables.** Workflow permissions have no variables
> scope, so with `GITHUB_TOKEN` alone the anchor is never published and **a stale cache restore
> goes undetected**. You need all three of these on every invocation of the Action (`claim` and
> `complete`):
>
> | Input | Value |
> |---|---|
> | `anchor-token` | A fine-grained personal access token (or GitHub App token) for this repository with **Variables: read and write**, stored as a secret, e.g. `${{ secrets.SYNTHE_ANCHOR_TOKEN }}`. |
> | `ledger-anchor` | `${{ vars.SYNTHE_LEDGER_ANCHOR }}` |
> | `ledger-hmac-key` | A secret, e.g. `${{ secrets.SYNTHE_LEDGER_HMAC_KEY }}` |
>
> Without `anchor-token`, the Action logs a warning and keeps going: the seal still catches
> corruption, but an older ledger snapshot passes as current.

Cache chaining alone cannot tell a *fresh* restore from a *stale* one: an
older snapshot, a forged empty file, or a deleted ledger all used to load as
valid, silently forgetting claims. Every ledger write is now sealed into a
hash chain under the reserved `"~synthe"` header (each head binds the previous
head, a monotonic sequence number, and the full entry set), and the Action
keeps an **out-of-cache anchor** -- the `SYNTHE_LEDGER_ANCHOR` repository
variable holding the last published `"seq:head"` -- that the restored ledger
must match or extend:

1. **Fetch anchor** (new step, before the phase): takes the anchor from the
   `ledger-anchor` input (pass `${{ vars.SYNTHE_LEDGER_ANCHOR }}`, no token
   needed), or reads the repository variable through the API with
   `anchor-token`. Empty / 404 means no anchor was ever published (first
   run): the checker seals a genesis chain. Any other fetch failure fails the
   workflow instead of running unanchored.
2. The checker verifies the chain seal and the anchor on every load. Older
   (`ledger_rollback`), divergent (`ledger_diverged`), or missing
   (`ledger_rollback`) ledgers fail closed with named reason codes.
3. **Publish anchor** (new step, after the save): writes the new head back to
   the repository variable (`--ledger-head` prints it).

To enable it:

- Pass `ledger-anchor: ${{ vars.SYNTHE_LEDGER_ANCHOR }}` so the checker sees
  the current anchor.
- Pass `anchor-token` so the Action can publish the new head. **`GITHUB_TOKEN`
  cannot write repository variables** (workflow permissions have no variables
  scope), so use a fine-grained personal access token or a GitHub App token
  with "Variables: read and write" on this repository, stored as a secret.
- Pass `ledger-hmac-key` from a CI secret (e.g.
  `${{ secrets.SYNTHE_LEDGER_HMAC_KEY }}`). **Both the key and the anchor are
  needed against someone who can write the ledger file:** without the key the
  seal is a public checksum, so a forger can mint a chain with a higher
  sequence number than the anchor; without the anchor, an older sealed
  snapshot or a deleted file cannot be told from a legitimate one. Once the
  key is set, an unsealed ledger is refused rather than adopted (adopt a
  genuine pre-seal ledger once with `ledger-bootstrap: 'true'`). Rotate the
  secret by setting the new value and keeping the old one available to the
  checker as `SYNTHE_LEDGER_HMAC_KEY_PREVIOUS` until every cached ledger has
  been re-sealed (the next save heals automatically).

Without an anchor, rollback detection is disabled and the checker logs a
warning (the seal still guards corruption). Without a key, a pre-chain ledger
is adopted in place as a new genesis chain -- entries preserved, no manual
migration step.

**Cache eviction recovery.** `actions/cache` entries expire after 7 days of
disuse. If the cache is totally evicted, the anchor still expects the old
chain and the run fails closed with `ledger_rollback`. Recover deliberately:
run once with `ledger-bootstrap: 'true'` -- anchor enforcement is skipped for
that run, a fresh genesis chain is sealed, and the anchor is republished.
(This is also the recovery if the ledger file is deleted.)

### Required caller workflow shape

```yaml
# .github/workflows/handoff.yml
name: Handoff

on:
  workflow_dispatch:        # or pull_request / your real trigger

# REQUIRED for cross-run exactly-one claims: every run that touches the
# ledger joins this one group, so GitHub runs them strictly one at a
# time, in order. Without it, two simultaneous runs can both ACCEPT the
# same packet (both restore the pre-claim snapshot). Do NOT set
# cancel-in-progress: a cancelled claimant would strand the queue.
concurrency:
  group: synthe-handoff-ledger
  cancel-in-progress: false

permissions:
  contents: read

jobs:
  handoff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # 1. CLAIM: validate + record RESERVED. Fails the job on REJECT.
      - name: Claim handoff
        id: claim
        uses: rohansiddam/Synthe/github-action@main
        with:
          packet: handoff.json
          registry: agents/registry.json
          workspace: .
          phase: claim
          ledger-anchor: ${{ vars.SYNTHE_LEDGER_ANCHOR }}
          anchor-token: ${{ secrets.SYNTHE_ANCHOR_TOKEN }}   # PAT/App token with Variables: write
          ledger-hmac-key: ${{ secrets.SYNTHE_LEDGER_HMAC_KEY }}

      # 2. THE EFFECT: the receiving agent does the actual work here.
      - name: Do the work
        run: ./run_receiver.sh

      # 3. COMPLETE: flip RESERVED -> COMPLETED and persist it. Runs even
      #    if the effect step failed? No: only complete an effect that
      #    actually happened. If the effect failed, leave the claim
      #    RESERVED; it expires to `unknown` after the TTL for
      #    reconciliation instead of pretending completion.
      - name: Complete handoff
        uses: rohansiddam/Synthe/github-action@main
        with:
          packet: handoff.json
          registry: agents/registry.json
          workspace: .
          phase: complete
          # The same three as the claim step. The complete phase restores, re-seals and
          # re-publishes the ledger too, and a ledger sealed with the HMAC key is refused
          # by a run without it.
          ledger-anchor: ${{ vars.SYNTHE_LEDGER_ANCHOR }}
          anchor-token: ${{ secrets.SYNTHE_ANCHOR_TOKEN }}
          ledger-hmac-key: ${{ secrets.SYNTHE_LEDGER_HMAC_KEY }}
```

Notes on the shape:

- The `concurrency` group belongs to the **caller** workflow: a
  composite action cannot declare one. Every workflow that uses this
  Action against the same repository ledger must use the **same group
  name**, or those workflows can still race each other (see "What is
  proven, what is not").
- Serialization costs throughput: handoff runs queue instead of running
  in parallel. For a claim ledger that is the correct trade.
- The group can also be declared per-job (`jobs.<id>.concurrency`) if a
  workflow has unrelated jobs that should not queue behind handoffs;
  the group string must still be identical everywhere the ledger is
  used.
- If you pass your own `ledger` path, the cache steps are skipped and
  persisting/completing that file between runs is up to you, but the
  ordering requirement is the same: only one claimant at a time against
  a given ledger state, or exactly-one is not guaranteed.

### Cache eviction is now loud (not silent)

`actions/cache` entries are evicted after 7 days unused (or past the
10 GB repo limit). Previously a restore miss silently started the run from
an empty ledger: every key reopened and exactly-once quietly became
at-most-once. Now the Action refuses to do that:

1. **Chain marker.** Every ledger the checker writes carries its chain
   seal under the reserved top-level key `"~synthe"` (see "Ledger integrity:
   sealed chain + out-of-cache anchor" above: `chain_seq`, `chain_prev`, `chain_head`, ...). The guard
   treats that header as the marker that a ledger came from a real chain.
   The `~` prefix is reserved: the checker REJECTs any packet whose
   `idempotency_key` starts with `~` (`reserved_idempotency_key`), and audit
   tooling should skip `~`-prefixed top-level keys when enumerating claims.
2. **Continuity guard.** After the restore step,
   `checker/ledger_guard.sh` runs before the checker phase. The restore
   signal is the restore step's `cache-matched-key` output (non-empty when
   the restore matched any cache entry), **not** `cache-hit`: the Action
   saves with key `synthe-ledger-<repo>-<run_id>-<attempt>-<phase>` but
   restores with the bare prefix `synthe-ledger-<repo>`, so every real
   restore comes from restore-keys prefix fallback and `cache-hit` (true
   only on an exact primary-key match) is never true on real GitHub.
   - restore matched a key + marker present → chain intact, proceed;
   - restore matched a key + no marker → legacy ledger (written before the
     marker existed): proceed with a warning; the checker seals it
     on the next write;
   - restore matched a key but no ledger file materialized → anomalous,
     proceed with a warning (this is not an eviction);
   - restore matched nothing + a ledger file is already present (created
     earlier in this job) → proceed;
   - restore matched nothing + this is the workflow's first run
     (`github.run_number == 1`) → genuine first run: proceed and
     initialize a fresh chain;
   - restore matched nothing + `ledger-bootstrap: 'true'` → operator-declared
     fresh chain: proceed with a warning (use for one run only, after
     reconciling);
   - restore matched nothing otherwise → **fail the run loudly** (`::error::`,
     non-zero exit) *before* the checker can ACCEPT against an empty
     ledger.

**If the guard fails:** do not just re-run. Reconcile any in-flight
effects against the receiver's effect receipts (the ledger is one layer;
the receipt is the source of truth), then run once with
`ledger-bootstrap: 'true'` and remove it afterwards. Duplicate protection
restarts empty for that run, so the reconciliation step is what keeps it
safe.

### Beyond the cache: durable backends (recommended)

The cache is best-effort storage with a 7-day idle expiry. If your
handoffs must stay duplicate-safe across longer idle windows, do not rely
on it:

- Pass the `ledger` input and persist that file in durable storage
  yourself: download it at job start and upload it at job end (object
  storage, a pinned artifact with retention sized to your idle window, a
  persistent volume — whatever your org already pays for). The
  cache/restore/save steps are skipped when `ledger` is set.
- The checker auto-detects the ledger format by suffix: `.json` for the
  plain file, `.sqlite` / `.sqlite3` for the crash-safe SQLite/WAL ledger
  (v2). For a durable backend, the SQLite format is the better file to
  persist.
- The `concurrency` group requirement is unchanged: whatever the backend,
  only one claimant at a time per ledger, or exactly-one is not guaranteed.

Choosing and paying for the hosting is the repository owner's decision;
the Action deliberately ships no backend service.

### What is proven, what is not

Proven:

- **Checker semantics** (unchanged by this hardening): 26 tests in
  `../tests/` — validator behavior, the RESERVED/COMPLETED/`unknown`
  conformance suite, and ledger invariants (including exactly-one-winner
  among concurrent processes sharing one filesystem).
- **The v0.2 cross-run failure**, reproduced in a local model:
  `simulate_two_runners.py --mode legacy` runs the real checker in two
  isolated workspaces that both restore from the same empty snapshot;
  both ACCEPT the same key.
- **The fix at simulation level**: with runs serialized and the second
  runner restoring the first runner's saved ledger, exactly one ACCEPT
  and a `duplicate` rejection; after a simulated complete step, a replay
  is rejected against the `COMPLETED` entry (`--mode fixed`,
  `--mode complete`; pinned by `tests/test_two_runner.py`).
- **Eviction is loud at simulation level**: `--mode evicted` wipes the
  cache snapshot between runs; the continuity guard fails the later run
  loudly before the checker runs, while the workflow's genuine first run
  still ACCEPTs and stamps the chain marker (pinned by
  `tests/test_two_runner.py` S4 and `tests/test_ledger_durability.py`).
- **Prefix restores are modeled**: `--mode prefix-restore` drives the real
  guard with real-GitHub restore semantics (save key
  `synthe-ledger-<repo>-<run_id>-<attempt>-<phase>`, restore via prefix
  fallback, `cache-hit` never true, `cache-matched-key` non-empty): a
  marked ledger restores intact, and a restored legacy ledger warns and
  continues instead of failing with a false EVICTED error (pinned by
  `tests/test_two_runner.py` S5).

Not yet proven:

- **Anything on real GitHub infrastructure.** The simulation models
  eviction as a snapshot wipe, prefix-fallback restores, and the guard's
  first-run signal as `github.run_number`; it does not model
  concurrency-group queueing behavior at scale, or cross-branch cache
  visibility. Until the one-time real two-runner verification workflow
  passes (including a forced-miss run to watch the guard fire),
  describe cross-run protection as "designed and simulation-tested", not
  as demonstrated.
- **Forks and other repositories.** Caches do not cross forks; a fork's
  runs start from an empty ledger.
- **Two different workflows (or a workflow that omits the group) sharing
  one ledger.** Serialization only covers runs that join the group.
- **High-stakes effects generally.** Even fully chained, the cache is
  best-effort storage. Keep the receiver's own effect receipt as the
  source of truth for reconciliation; the ledger is one layer.

## Inputs

| Input       | Required | Default | Description |
|-------------|----------|---------|-------------|
| `packet`    | yes      | —       | Path to the handoff packet JSON. |
| `registry`  | no       | —       | Path to the agent registry JSON (canonical ids + aliases). Without it, identity checks are skipped. Its signature is checked only when `SYNTHE_REGISTRY_GENESIS_KEY` is set in the job's `env`; see [`docs/REGISTRY_GENESIS_KEY.md`](../docs/REGISTRY_GENESIS_KEY.md). |
| `ledger`    | no       | *(managed)* | Path to an idempotency ledger JSON for duplicate detection. Leave unset and the Action persists `.synthe/ledger.json` across runs via `actions/cache` (see above). Set it only if you manage that file's persistence yourself. |
| `ledger-hmac-key` | no | — | HMAC key sealing the ledger chain. Pass a secret, e.g. `${{ secrets.SYNTHE_LEDGER_HMAC_KEY }}`, on both phases. |
| `ledger-anchor` | no | — | The published chain head: `${{ vars.SYNTHE_LEDGER_ANCHOR }}`. Reading it needs no token. Empty on the first run. |
| `anchor-token` | no | — | Token that writes the `SYNTHE_LEDGER_ANCHOR` repository variable after each run. **`GITHUB_TOKEN` can't**: use a fine-grained token with "Variables: read and write" on this repository, from a secret. Without it, stale cache restores aren't detected. |
| `ledger-bootstrap` | no | `'false'` | Set to `'true'` for ONE run to declare a fresh ledger chain after an eviction-guard failure (reconcile in-flight effects first) or when adding the Action to a workflow that already has runs. |
| `workspace` | no       | `.`     | Root for artifact existence/hash checks. |
| `phase`     | no       | `claim` | `claim`: validate + record the key as `RESERVED`. `complete`: after the effect is real, flip the key to `COMPLETED` (same packet/registry/ledger inputs). |

## Output

| Output     | Description |
|------------|-------------|
| `decision` | `ACCEPT` or `REJECT` (claim phase); `COMPLETED` or `REJECT` (complete phase). |

## Local test

The entrypoints are plain bash scripts, so you can simulate CI locally:

```bash
# claim
HANDOFF_PACKET=../examples/valid.json \
HANDOFF_REGISTRY=../examples/registry.json \
HANDOFF_LEDGER=ledger.json \
HANDOFF_WORKSPACE=.. \
  bash checker/run_check.sh

# complete (after the "effect"), then replay the claim to see the
# terminal duplicate rejection
HANDOFF_PACKET=../examples/valid.json HANDOFF_LEDGER=ledger.json \
  bash checker/run_complete.sh
HANDOFF_PACKET=../examples/valid.json \
HANDOFF_REGISTRY=../examples/registry.json \
HANDOFF_LEDGER=ledger.json \
HANDOFF_WORKSPACE=.. \
  bash checker/run_check.sh   # -> REJECT duplicate
```

Two-runner simulation (local model of the cross-run behavior, including
the v0.2 failure mode):

```bash
python3 simulate_two_runners.py            # all modes; exit 0 = expectations hold
python3 simulate_two_runners.py --mode legacy   # reproduces the double-ACCEPT
```
