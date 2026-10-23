# SPDX-License-Identifier: Apache-2.0
"""How carefully a push deserves to be read: routine, review or high.

One classification, used by two readers so they never disagree:
- the approval card (synthe_approve.py) shows it to the human, from the broker's staged detail;
- the broker (synthe_commit.py) acts on it for a risk-aware lane grant: a grant that carries
  `"auto_approve": [...]` pushes on its own only the tiers it lists, and anything else stays staged for
  a human (reason `risk_escalated`).

It is computed only from the broker's own copy of the change (its diff, the files every pushed commit
touches, the commit count), never from anything the agent wrote about the push. It is a heuristic: it
reads paths and sizes, not code, so a malicious change to an ordinary-looking source file is routine.

The path lists are a policy: the operator may replace them in broker.json
(`effects.git_push.risk.high_paths` / `review_paths`). The effective rules, thresholds included, are
digested into a risk-aware grant's lineage, so changing them makes the grant `template_stale`.
Stdlib only.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import re

TIERS = ("routine", "review", "high")
# Thresholds (specs/approval-card-v2.md). Lines are insertions + deletions from the broker's own diff.
REVIEW_LINES, HIGH_LINES = 200, 400
HIGH_DELETED_FILES = 10
REVIEW_COMMITS, HIGH_COMMITS = 10, 30
MAX_PATCH = 200_000  # the broker's display limit for a diff (staged_detail): past it, nobody read it all
# Paths whose change can run code, ship a dependency, alter CI or hold a secret. A match on CI or a
# secrets-like name makes the push high risk; the rest make it worth a check.
HIGH_PATHS = (".github/workflows/*", ".github/actions/*", ".gitlab-ci.yml", ".circleci/*", "Jenkinsfile",
              "*.pem", "*.key", "id_rsa*", "id_ed25519*", ".env", ".env.*")
REVIEW_PATHS = ("Dockerfile", "Dockerfile.*", "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
                "poetry.lock", "uv.lock", "Cargo.lock", "go.sum", "setup.py", "pyproject.toml", "Makefile",
                "scripts/*.sh", "bin/*", "CODEOWNERS", ".gitattributes")
RULE_KEYS = ("high_paths", "review_paths")  # what an operator may set in effects.git_push.risk
MAX_PATTERNS = 200
MAX_RISK_PATHS = 50  # sensitive paths listed in a receipt (the count is always exact)

# C0/C1 controls except tab and newline (ESC starts ANSI sequences; CR overwrites a line), DEL,
# and the bidi controls that reorder what you read (Trojan Source).
_CONTROL = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f؜‎‏‪-‮⁦-⁩]")


def clean(text, one_line: bool = False) -> str:
    """Agent-controlled text made safe to print: control codes become visible escapes."""
    s = "" if text is None else str(text)
    if one_line:
        s = s.replace("\n", "\\n")

    def esc(m):
        c = ord(m.group())
        return f"\\x{c:02x}" if c < 0x100 else f"\\u{c:04x}"
    return _CONTROL.sub(esc, s)


def matches(path: str, patterns) -> bool:
    """A pattern with a slash matches the path from the repository root; one without matches the file
    name at any depth (so a nested lockfile or .env counts like a top-level one)."""
    name = path.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatchcase(path if "/" in p else name, p) for p in patterns)


def shortstat(stat) -> tuple[int, int]:
    """(insertions, deletions) from git's --shortstat line; (0, 0) when absent."""
    text = stat if isinstance(stat, str) else ""
    ins = re.search(r"(\d+) insertions?\(\+\)", text)
    dels = re.search(r"(\d+) deletions?\(-\)", text)
    return (int(ins.group(1)) if ins else 0, int(dels.group(1)) if dels else 0)


# --------------------------------------------------------------------------
# the rules (a policy: the operator's, with these defaults)

def load_rules(conf=None) -> dict:
    """The effective rules from the operator's `effects.git_push.risk` (None: the defaults). A list
    given there replaces the default list. Raises ValueError on anything malformed: a broker never
    guesses what a risk policy meant."""
    if conf is None:
        conf = {}
    if not isinstance(conf, dict) or set(conf) - set(RULE_KEYS):
        raise ValueError(f"effects.git_push.risk takes only {', '.join(RULE_KEYS)}")
    out = {"v": 1, "high_paths": list(HIGH_PATHS), "review_paths": list(REVIEW_PATHS),
           "review_lines": REVIEW_LINES, "high_lines": HIGH_LINES, "high_deleted_files": HIGH_DELETED_FILES,
           "review_commits": REVIEW_COMMITS, "high_commits": HIGH_COMMITS, "max_patch": MAX_PATCH}
    for k in RULE_KEYS:
        if k in conf:
            v = conf[k]
            if not isinstance(v, list) or len(v) > MAX_PATTERNS or \
                    any(not isinstance(p, str) or not p.strip() or "\x00" in p or len(p) > 256 for p in v):
                raise ValueError(f"effects.git_push.risk.{k} must be a list of up to {MAX_PATTERNS} glob patterns")
            out[k] = list(v)
    return out


def rules_digest(r: dict) -> str:
    """SHA-256 of the canonical rules: what a risk-aware grant's lineage pins."""
    return hashlib.sha256(json.dumps(r, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                          .encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# the assessment

def _signals(changes, r: dict) -> list:
    """[(tier index, reason, sensitive paths)] in the order checked, from the broker's changes record:
    {"available", "stat", "files" (the net diff), "touched" (every path every pushed commit touches),
    "commits", "commit_count", "patch_truncated"}."""
    ch = changes if isinstance(changes, dict) else {}
    found: list = []

    def flag(tier: str, reason: str, paths=()):
        found.append((TIERS.index(tier), reason, list(paths)))

    if not isinstance(changes, dict) or ch.get("available") is not True:
        flag("high", "the broker can't show its copy of the change")
    if ch.get("patch_truncated"):
        flag("high", "the diff is larger than the broker's display limit")
    ins, dels = shortstat(ch.get("stat"))
    lines = ins + dels
    if lines >= r["high_lines"]:
        flag("high", f"{lines} lines changed")
    elif lines >= r["review_lines"]:
        flag("review", f"{lines} lines changed")
    files = [f for f in ch.get("files") or [] if isinstance(f, dict)]
    deleted = sum(1 for f in files if str(f.get("status", "")).startswith("D"))
    if deleted and (deleted >= r["high_deleted_files"] or (len(files) >= 4 and deleted * 4 > len(files))):
        flag("high", f"deletes {deleted} file{'s' if deleted != 1 else ''}")
    elif deleted:
        flag("review", f"deletes {deleted} file{'s' if deleted != 1 else ''}")
    # Paths: the net diff, then every path any pushed commit touched (the remote receives every
    # intermediate commit: a workflow added and removed again is still pushed).
    every = [str(f.get("path", "")) for f in files]
    every += [str(f.get("path", "")) for f in ch.get("touched") or [] if isinstance(f, dict)]
    every = list(dict.fromkeys(every))
    for tier, patterns in (("high", r["high_paths"]), ("review", r["review_paths"])):
        hits = [p for p in every if matches(p, patterns)]
        if hits:
            more = f" and {len(hits) - 1} more" if len(hits) > 1 else ""
            flag(tier, f"changes {clean(hits[0], True)}{more}", hits)
    n_commits = ch.get("commit_count")
    if not isinstance(n_commits, int) or isinstance(n_commits, bool):
        n_commits = len(ch.get("commits") or [])
    if n_commits >= r["high_commits"]:
        flag("high", f"{n_commits} commits")
    elif n_commits >= r["review_commits"]:
        flag("review", f"{n_commits} commits")
    return found


def _verdict(found: list) -> dict:
    if not found:
        return {"tier": "routine", "reasons": []}
    found = sorted(found, key=lambda x: -x[0])  # stable: highest tier first, then the order checked
    return {"tier": TIERS[found[0][0]], "reasons": [s[1] for s in found]}


def assess(detail: dict, rules: dict | None = None) -> dict:
    """The approval card's assessment of a staged push: {"tier": routine|review|high, "reasons": [...]}.
    Computed only from the broker's record (target, its own diff, file list, commits); never from
    anything the agent wrote about the push. Reasons are short plain sentences, already cleaned."""
    r = rules or load_rules()
    eff = detail.get("effect") if isinstance(detail, dict) else None
    eff = eff if isinstance(eff, dict) else {}
    found = _signals(detail.get("changes") if isinstance(detail, dict) else None, r)
    # About the target, not the change: worth a look on the card. A lane never escalates on it (the
    # human already signed the branch pattern, and pushes are fast-forward only), see assess_change.
    if eff.get("expected_old") not in (None, "new"):
        found.append((TIERS.index("review"), "updates an existing branch", []))
    return _verdict(found)


def assess_change(changes: dict, rules: dict | None = None) -> dict:
    """What the broker acts on for a risk-aware lane: the same signals as the card, from the change
    alone. {"tier", "reasons", "paths": the sensitive paths matched (at most MAX_RISK_PATHS),
    "sensitive_paths": how many}. For a push that goes to a human, the card's tier is never lower."""
    found = _signals(changes, rules or load_rules())
    paths = list(dict.fromkeys(p for s in found for p in s[2]))
    return {**_verdict(found), "paths": paths[:MAX_RISK_PATHS], "sensitive_paths": len(paths)}


def stricter(mine: dict, theirs) -> dict:
    """The card's assessment, raised to the broker's own (`risk` in the staged detail) when that is
    stricter, so a push the broker escalated never looks calmer on the card. Never lowered by it."""
    if not isinstance(theirs, dict) or theirs.get("tier") not in TIERS \
            or TIERS.index(theirs["tier"]) <= TIERS.index(mine["tier"]):
        return mine
    extra = [clean(x, True) for x in theirs.get("reasons") or [] if isinstance(x, str)]
    return {"tier": theirs["tier"], "reasons": list(dict.fromkeys(extra + mine["reasons"]))}
