# Skill admission scanning (`synthe-skill`)

A skill is trusted the moment it is installed, but Synthe's runtime gates only
see what a skill does once it is inside. `synthe-skill admit` narrows that gap:
it statically scans a skill bundle for known-bad patterns and records a
*signed admission receipt* so there is an auditable record of what was
scanned, when, and what the scanner found.

**This is a heuristic filter, not a security proof.** A clean ACCEPT means
"no known-bad pattern found", never "this skill is safe". See
"What this cannot catch" below.

## Usage

```bash
# Scan a bundle and record the signed receipt (exit 0 = ACCEPT, 2 = REJECT)
synthe-skill admit ./my-skill --key admitter.json --store admissions.json

# Show the verdict from the latest SIGNED receipt (exit 0/2/3, see below)
synthe-skill status my-skill --store admissions.json --registry agents.json

# Re-check the bundle on disk against the receipt (adds freshness info)
synthe-skill status my-skill --store admissions.json --registry agents.json \
    --bundle ./my-skill

# Offline audit of the receipt chain and signatures
synthe-skill verify --store admissions.json --registry agents.json
```

## Verdicts

Each of the nine attack classes contributes its highest-weight finding; the
score is the clamped sum. Default policy: score >= 70 -> REJECT,
40-69 -> ACCEPT_WITH_WARNINGS, < 40 -> ACCEPT. Thresholds are configurable
(`--reject-at`, `--warn-at`, `--policy`, `--ignore`).

| Attack class | What it looks for |
|---|---|
| `credential_access` | Reads of `~/.aws`, `~/.ssh`, keychain, netrc, credential-shaped env vars. Always weight 85. A `## Permissions` section in SKILL.md does **not** reduce the score: self-declared permissions are unverified, and the finding says so. |
| `remote_script_fetch` | `curl ... \| sh`, `wget ... \| sh`, `urlopen`+`exec`, PowerShell download-and-execute patterns. |
| `hidden_instruction` | HTML comments with imperative language, zero-width characters, invisible CSS/ARIA, empty-anchor links, base64 blobs that decode to instruction-like text. |
| `mcp_tool_poisoning` | Tool definitions shadowing built-in tool names (`read_file`, `bash`, ...), directive language in tool descriptions. |
| `prompt_injection_pattern` | "Ignore all previous instructions", role markers, prompt-reveal requests, jailbreak phrasing. |
| `data_exfiltration_path` | Webhook catcher URLs, `curl` POSTs, external `requests.post`, raw sockets to external hosts, env-read + external-URL co-occurrence. |
| `persistence_mechanism` | cron, launchd, systemd units, shell-rc appends, Windows Run keys, git hooks, autostart entries. |
| `risky_dependency` | Dependencies fetched from remote URLs/tarballs instead of a package index; unpinned `*` versions (warning weight). |
| `unscanned_file` | Files the scanner could not fully read (see below). Scripts and native executables are untrusted by default (weight 80); other content is a warning (25). |

## Unscanned files

Files are never silently skipped. Per file:

- **Over the 1 MB scan limit:** the first megabyte is scanned normally, and an
  `unscanned_file` finding records that the remainder was not scanned.
- **Binary / undecodable:** the file is classified by shebang line, magic
  bytes (ELF, PE, Mach-O), and extension. Scripts and executables get a
  REJECT-weight finding (80); anything else gets a warning (25).

## Receipts and `status`

Every admission, including REJECTs, is recorded as a signed receipt in the
store: a seq/prev hash chain plus an Ed25519 signature under the
`synthe/admission-receipt/v1` domain. Each receipt pins the skill version and
a sha256 manifest of every file in the bundle, so any later change to the
bundle is detectable (`status --bundle` reports `admission_stale`).

`status` is verify-by-default:

- The verdict comes from the **latest signed receipt**, never the unsigned
  `data["skills"]` index (the index is only a lookup cache).
- The chain is always verified and `--registry` is **required**: without a
  verified signature, `status` cannot tell a real verdict from a forged one.
- The unsigned index is cross-checked against the receipt; any disagreement
  is reported as `index_mismatch`.

Exit codes: **0** = verified ACCEPT; **2** = verified REJECT, or the bundle
changed since admission (`admission_stale`); **3** = broken chain, bad
signature, or index/receipt mismatch. A 3 means the *record itself* cannot
be trusted — treat the skill as unadmitted until the store is investigated.

## What this cannot catch

Stated plainly, so nobody mistakes a clean scan for a guarantee:

- **Padding evasion.** Files past the 1 MB scan limit are only partially
  scanned. The unscanned remainder is *flagged*, not *inspected*: a payload
  placed entirely after the first megabyte will not be seen. The finding
  exists so the gap is visible, not closed.
- **Obfuscated payloads.** Encoded, encrypted, or packed blobs that do not
  match the patterns; logic split across files so no single file looks
  malicious; novel exfiltration channels not in the pattern list. The
  detectors are regex and structural heuristics over known shapes.
- **Runtime-fetched code.** URLs fetched at runtime, dependencies resolved
  from package indexes (version drift, dependency confusion), code downloaded
  after admission, or skills that update themselves. The receipt pins the
  bundle *as scanned*; anything the skill pulls in later is outside it.
- **Self-declared permissions.** A `## Permissions` section is the skill's
  own claim about itself. The scanner records the claim in the finding
  detail but cannot verify it, and a declaration never lowers the score.
- **Behavior.** Nothing is executed. What the skill does at runtime is not
  observed, only what its files look like.

The signed receipt proves *what was scanned and when*, not that the skill is
safe. Admission is one gate among several; treat it accordingly.
