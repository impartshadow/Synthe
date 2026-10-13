#!/usr/bin/env bash
# Ledger-chain continuity guard for the Handoff Contract Check GitHub Action.
#
# Runs AFTER the actions/cache restore step and BEFORE the checker phase.
# actions/cache entries are evicted after 7 days unused (or past the 10 GB
# repo limit). Before this guard, a restore miss silently started the run
# from an empty ledger, downgrading exactly-once duplicate protection to
# at-most-once with no signal. This guard makes that LOUD:
#
#   exit 0 -> the ledger chain is intact, or this is a declared / genuine
#             first run: the checker may proceed.
#   exit 1 -> the restore matched NOTHING but a ledger chain was EXPECTED
#             (a previous run saved one): fail the run before the checker
#             can ACCEPT against an empty ledger.
#
# THE RESTORE SIGNAL: the Action saves with a per-run/per-phase key
# (synthe-ledger-<repo>-<run_id>-<attempt>-<phase>) but restores with the
# bare prefix (synthe-ledger-<repo>), so real restores always come from
# restore-keys PREFIX fallback. actions/cache sets `cache-hit=true` ONLY on
# an exact primary-key match, so on real GitHub `cache-hit` is NEVER true.
# The signal below is therefore steps.restore.outputs.cache-matched-key:
# non-empty when the restore matched ANY entry (exact or prefix fallback),
# empty when it matched nothing. (v1 used cache-hit and misread every real
# prefix restore as a miss -- a restored legacy ledger got a FALSE
# "EVICTED" failure.)
#
# Configured via environment variables (set by action.yml):
#   LEDGER_FILE       path to the Action-managed ledger (default .synthe/ledger.json)
#   CACHE_MATCHED_KEY the restore step's `cache-matched-key` output
#                     ("" when nothing matched)
#   RUN_NUMBER        github.run_number (1 on the workflow's first-ever run)
#   LEDGER_BOOTSTRAP  'true' to declare a fresh chain for this one run
#                     (operator recovery / first Action use in an old workflow)
set -u

LEDGER_FILE="${LEDGER_FILE:-.synthe/ledger.json}"
CACHE_MATCHED_KEY="${CACHE_MATCHED_KEY:-}"
RUN_NUMBER="${RUN_NUMBER:-}"
BOOTSTRAP="${LEDGER_BOOTSTRAP:-false}"
MARKER_KEY="~synthe"

has_marker() {
  # True iff LEDGER_FILE is a JSON object carrying the "~synthe" chain header.
  python3 - "$LEDGER_FILE" "$MARKER_KEY" <<'EOF'
import json, sys
path, key = sys.argv[1], sys.argv[2]
try:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
except (OSError, ValueError):
    sys.exit(1)
sys.exit(0 if isinstance(data, dict) and isinstance(data.get(key), dict) else 1)
EOF
}

has_ledger_file() {
  [[ -f "$LEDGER_FILE" ]]
}

fail_evicted() {
  # Loud failure: never silently start from an empty ledger.
  echo "::error::Synthe ledger chain BROKEN: the actions/cache restore for '$LEDGER_FILE' matched no cache entry, and this is not the workflow's first run (run #${RUN_NUMBER:-unknown}). The previous ledger was probably EVICTED (cache entries expire after 7 days unused, or past the 10 GB repo limit) or the previous run's save never landed. Starting from an empty ledger would silently lose duplicate protection (exactly-once downgrades to at-most-once), so this run REFUSES to continue."
  echo "::error::Recovery: reconcile any in-flight effects against the receiver's effect receipts, then re-run ONCE with 'ledger-bootstrap: \"true\"' to declare a fresh ledger chain (duplicate protection restarts empty for that run). See github-action/README.md 'Cache eviction is now loud'."
  exit 1
}

if [[ -n "$CACHE_MATCHED_KEY" ]]; then
  # The restore matched an entry (exact or, on real GitHub, restore-keys
  # prefix fallback): a ledger chain was handed to this run.
  if has_marker; then
    echo "Synthe ledger guard: cache restore matched '$CACHE_MATCHED_KEY' and the ledger carries its chain marker - chain intact, proceeding."
    exit 0
  fi
  if has_ledger_file; then
    # Restored a legacy ledger (written before the chain marker existed):
    # real claims, no identity yet. WARN and continue -- this is every
    # current user's first run after upgrading, not an eviction.
    echo "::warning::Synthe ledger guard: cache restore matched '$CACHE_MATCHED_KEY' but the ledger has no \"~synthe\" chain seal (written before ledgers were sealed). Proceeding; the checker seals it on the next write. If ledger-hmac-key is set, the checker refuses unsealed ledgers instead: run once with ledger-bootstrap: 'true' to adopt it."
    exit 0
  fi
  echo "::warning::Synthe ledger guard: cache restore matched '$CACHE_MATCHED_KEY' but no ledger file is present in the workspace (nothing was extracted from the matched entry). Proceeding with a fresh ledger; the checker will initialize a new chain identity."
  exit 0
fi

# The restore matched nothing.
if has_ledger_file; then
  echo "::notice::Synthe ledger guard: cache restore matched nothing, but a ledger file is already present (e.g. created earlier in this job). Proceeding."
  exit 0
fi
if [[ "$BOOTSTRAP" == "true" ]]; then
  echo "::warning::Synthe ledger guard: LEDGER_BOOTSTRAP=true - operator declared a fresh ledger chain for this run. Duplicate protection restarts EMPTY; only use this after reconciling in-flight effects."
  exit 0
fi
if [[ "$RUN_NUMBER" == "1" ]]; then
  echo "::notice::Synthe ledger guard: first workflow run (no cache snapshot yet) - initializing a fresh ledger chain."
  exit 0
fi
fail_evicted
