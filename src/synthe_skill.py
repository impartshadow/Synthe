#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Synthe skill admission scanning (CLI-first, stdlib only).

A skill is trusted the moment it is installed, but Synthe's runtime gates only
see what a skill does once it is inside. `synthe-skill admit` closes that gap a
little: it statically scans a skill bundle (SKILL.md, bundled scripts, declared
dependencies, referenced remote URLs) for nine attack classes and returns a
typed verdict shaped like the handoff gate -- ACCEPT / REJECT with
machine-readable reason codes, a 0-100 risk score, and exact findings.

  admit   BUNDLE --key KEYFILE [--store FILE] [--registry REG] [--name N]
                 [--reject-at 70] [--warn-at 40] [--policy POLICY.json]
          Scan the bundle, record the signed admission receipt, print the verdict.
          Exit 0 = ACCEPT (or ACCEPT_WITH_WARNINGS), 2 = REJECT.
  status  NAME --store FILE --registry REG [--bundle DIR]
          Show the verdict taken from the latest SIGNED receipt (never the
          unsigned index), verify the chain and the receipt signature, and
          cross-check the unsigned index against the receipt.
          Exit 0 = verified ACCEPT, 2 = verified REJECT or stale bundle,
          3 = broken chain, bad signature, or index/receipt mismatch.
  verify  --store FILE [--registry REG]
          Offline audit: check the receipt chain (seq/prev) and every receipt
          signature against the registry.

Attack classes (each is a reason code):
  credential_access, remote_script_fetch, hidden_instruction,
  mcp_tool_poisoning, prompt_injection_pattern, data_exfiltration_path,
  persistence_mechanism, risky_dependency, unscanned_file.

Files the scanner cannot fully read are NOT silently skipped: files over the
1 MB scan limit get their first megabyte scanned plus an `unscanned_file`
finding for the remainder, and binary/undecodable files get an
`unscanned_file` finding classified by extension, shebang, and magic bytes
(script or native-executable types score 80, everything else 25).

Scoring: each class contributes its highest-weight finding (0-100); the verdict
score is the clamped sum. Admission policy: score >= reject_at (default 70) is
REJECT; score >= warn_at (default 40) is ACCEPT_WITH_WARNINGS; below that is
ACCEPT. A REJECT is still recorded as a signed receipt, so denied admissions
are auditable too.

The receipt pins the skill version and a sha256 manifest of every file in the
bundle. Changing any file invalidates the receipt: `status --bundle` reports
it stale until the skill is re-scanned (a re-scan appends a new receipt; the
old ones stay in the chain as history).

This is best-effort static scanning, not a standalone scanner product: it
catches the documented ClawHub/ClawHavoc-shaped patterns (credential theft
that behaves correctly at runtime), and it will miss novel or obfuscated
attacks. Treat a clean ACCEPT as "no known-bad pattern found", not as proof
of safety.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import datetime as dt
import hashlib
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import synthe_crypto as sc  # noqa: E402
from synthe_sign import load_key  # noqa: E402

ADMISSION_SIG_DOMAIN = "synthe/admission-receipt/v1"

CREDENTIAL_ACCESS = "credential_access"
REMOTE_SCRIPT_FETCH = "remote_script_fetch"
HIDDEN_INSTRUCTION = "hidden_instruction"
MCP_TOOL_POISONING = "mcp_tool_poisoning"
PROMPT_INJECTION = "prompt_injection_pattern"
DATA_EXFILTRATION = "data_exfiltration_path"
PERSISTENCE = "persistence_mechanism"
RISKY_DEPENDENCY = "risky_dependency"
UNSCANNED_FILE = "unscanned_file"

ATTACK_CLASSES = (CREDENTIAL_ACCESS, REMOTE_SCRIPT_FETCH, HIDDEN_INSTRUCTION,
                  MCP_TOOL_POISONING, PROMPT_INJECTION, DATA_EXFILTRATION,
                  PERSISTENCE, RISKY_DEPENDENCY, UNSCANNED_FILE)

DEFAULT_REJECT_AT = 70
DEFAULT_WARN_AT = 40
MAX_SCAN_BYTES = 1_000_000  # per file; larger files are hashed but not content-scanned

# Tool names a skill must never shadow: redefining one lets the skill intercept
# calls the operator believes go to the real tool.
BUILTIN_TOOL_NAMES = {
    "read_file", "write_file", "edit_file", "list_files", "bash", "exec",
    "shell", "run_command", "run", "terminal", "execute", "search", "grep",
    "synthe_validate_handoff", "synthe_propose_effect",
}


# ---------------------------------------------------------------------------
# findings
# ---------------------------------------------------------------------------

def _finding(code: str, weight: int, rel: str, line: int | None, excerpt: str,
             detail: str) -> dict:
    return {"code": code, "weight": int(weight), "file": rel, "line": line,
            "excerpt": excerpt[:300], "detail": detail}


def _iter_scannable(bundle: Path):
    """(rel, text, reasons, head, size) for every file in the bundle, sorted.

    text is the decodable content (the first MAX_SCAN_BYTES for over-limit
    files), or None when the content is binary/undecodable. reasons lists why
    the file was not fully scanned: "size" (over the byte limit), "binary"
    (NUL bytes / undecodable), or [] when fully scanned. head is the first
    8 KiB of raw bytes for type classification, size the full byte count.
    """
    for path in sorted(bundle.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        rel = path.relative_to(bundle).as_posix()
        if rel.startswith(".git/"):
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        try:
            with path.open("rb") as fh:
                chunk = fh.read(MAX_SCAN_BYTES + 1)  # +1 to detect over-limit
        except OSError:
            continue
        reasons = []
        over_limit = len(chunk) > MAX_SCAN_BYTES
        chunk = chunk[:MAX_SCAN_BYTES]
        head = chunk[:8192]
        if b"\x00" in head:
            text = None
            reasons.append("binary")
        else:
            try:
                text = chunk.decode("utf-8")
            except UnicodeDecodeError:
                text = chunk.decode("latin-1")
            if over_limit:
                reasons.append("size")
        yield rel, text, reasons, head, size


_SCRIPT_EXTS = {".sh", ".bash", ".zsh", ".py", ".pyw", ".js", ".mjs", ".cjs",
                ".ts", ".ps1", ".psm1", ".bat", ".cmd", ".rb", ".pl", ".php",
                ".lua", ".awk", ".fish"}
_EXEC_EXTS = {".exe", ".dll", ".so", ".dylib", ".bin", ".elf", ".msi"}
# ELF, PE (MZ), Mach-O (32/64-bit, both endians), universal/fat binaries.
_EXEC_MAGICS = (b"\x7fELF", b"MZ",
                b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce",
                b"\xca\xfe\xba\xbe")


def _classify_unscanned(rel: str, head: bytes) -> tuple[int, str]:
    """(weight, kind) for a file the scanner could not fully read.

    Scripts and native executables are untrusted by default (REJECT weight
    80): an unscanned script/executable is treated as hostile. Anything else
    gets a warning (25).
    """
    if head[:2] == b"#!":
        return 80, "script (shebang line)"
    if any(head.startswith(m) for m in _EXEC_MAGICS):
        return 80, "native executable (magic bytes)"
    name = rel.lower().rsplit("/", 1)[-1]
    ext = "." + name.rsplit(".", 1)[-1] if "." in name else ""
    if ext in _SCRIPT_EXTS:
        return 80, f"script ({ext} extension)"
    if ext in _EXEC_EXTS:
        return 80, f"native executable ({ext} extension)"
    return 25, "non-executable content"


def detect_unscanned_file(rel: str, reasons: list, head: bytes, size: int) -> list:
    weight, kind = _classify_unscanned(rel, head)
    parts = []
    if "size" in reasons:
        parts.append(f"file is {size:,} bytes, over the {MAX_SCAN_BYTES:,}-byte "
                     f"scan limit: only the first {MAX_SCAN_BYTES:,} bytes were "
                     "scanned, the remainder was not")
    if "binary" in reasons:
        parts.append("content could not be decoded as text (NUL bytes present) "
                     "and was not scanned")
    parts.append(f"classified as {kind}")
    return [_finding(UNSCANNED_FILE, weight, rel, None,
                     "unscanned: " + kind, "; ".join(parts))]


def _frontmatter(text: str) -> dict:
    """Minimal YAML-frontmatter reader: only top-level `key: value` lines."""
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    if end < 0:
        return {}
    out = {}
    for line in text[3:end].splitlines():
        m = re.match(r"^\s*([A-Za-z0-9_-]+)\s*:\s*(.*?)\s*$", line)
        if m:
            out[m.group(1).lower()] = m.group(2).strip().strip("'\"")
    return out


def _manifest(bundle: Path) -> dict:
    """relpath -> sha256 for every file (text or binary) in the bundle."""
    out = {}
    for path in sorted(bundle.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        rel = path.relative_to(bundle).as_posix()
        if rel.startswith(".git/"):
            continue
        h = hashlib.sha256()
        try:
            with path.open("rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    h.update(chunk)
        except OSError:
            continue
        out[rel] = h.hexdigest()
    return out


def _bundle_digest(manifest: dict) -> str:
    canon = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canon).hexdigest()


# ---------------------------------------------------------------------------
# the eight content detectors; each yields findings. detect_unscanned_file is
# driven separately by scan_bundle because unscanned files have no text.
# ---------------------------------------------------------------------------

_CRED_RES = [
    (r"(?:~|\\$HOME)?/\.aws/credentials", "reads AWS credential file"),
    (r"(?:~|\\$HOME)?/\.ssh/(?:id_[a-z]+|known_hosts|config)", "reads SSH private material"),
    (r"(?:~|\\$HOME)?/\.netrc", "reads netrc credentials"),
    (r"(?:~|\\$HOME)?/\.config/(?:gh|gcloud|aws)/", "reads CLI credential stores"),
    (r"security\s+find-generic-password", "queries the macOS keychain"),
    (r"Login Data", "reads a browser credential database"),
    (r"(?:os\.environ\[|os\.getenv\(|getenv\(\s*)[\"'][\w]*(?:SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY)[\w]*[\"']",
     "reads a credential-shaped environment variable"),
    (r"process\.env\[?[\"'][\w]*(?:SECRET|TOKEN|PASSWORD|API_KEY)[\w]*[\"']?\]?",
     "reads a credential-shaped environment variable"),
]

_CRED_DECLARED_RE = re.compile(r"(?im)^#{0,4}\s*(permissions|declared access|credential access|secrets)\b")


def detect_credential_access(rel: str, text: str, skill_md: str) -> list:
    # No discount for declared permissions: a "## Permissions" section is the
    # skill's own claim about itself, and this scanner cannot verify claims.
    # The finding notes the declaration so a human reviewer can judge it.
    declared = bool(_CRED_DECLARED_RE.search(skill_md or ""))
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        for pat, what in _CRED_RES:
            if re.search(pat, line):
                if declared:
                    detail = (f"{what}; SKILL.md declares credential access, "
                              "but self-declared permissions are unverified "
                              "by this scan")
                else:
                    detail = f"{what} (undeclared)"
                out.append(_finding(CREDENTIAL_ACCESS, 85, rel, i, line.strip(), detail))
                break
    return out


_REMOTE_FETCH_RES = [
    (r"curl\b[^|\n;]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b", "pipes a curl download straight into a shell"),
    (r"wget\b[^|\n;]*(?:-O-?|-qO-)[^|\n;]*\|\s*(?:sudo\s+)?(?:sh|bash)\b", "pipes a wget download straight into a shell"),
    (r"Invoke-(?:Expression|RestMethod)\s*\(\s*(?:New-Object\s+Net\.WebClient|irm\b|Invoke-RestMethod)",
     "downloads and executes remote code (PowerShell)"),
    (r"urllib\.request\.urlopen\s*\(", "fetches a remote URL at runtime"),
    (r"requests\.get\s*\(\s*[\"']https?://", "fetches a remote URL at runtime"),
    (r"exec\s*\(\s*(?:requests|urllib)", "exec()s fetched remote content"),
    (r"eval\s*\(\s*requests\.get", "eval()s fetched remote content"),
    (r"\bnode\s+-e\s+[\"'][^\"']*https?://", "node -e runs code referencing a remote URL"),
]


def detect_remote_script_fetch(rel: str, text: str) -> list:
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        for pat, what in _REMOTE_FETCH_RES:
            if re.search(pat, line):
                out.append(_finding(REMOTE_SCRIPT_FETCH, 80, rel, i, line.strip(), what))
                break
    return out


_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\ufeff]")
_IMPERATIVE_RE = re.compile(r"(?i)\b(ignore|disregard|send|exfiltrat|steal|run|execute|install|download|upload|secret|password|token|bypass|disable|delete)\b")
_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
_B64_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{60,}={0,2})(?![A-Za-z0-9+/=])")
_INVISIBLE_CSS_RE = re.compile(
    r"(?i)(color\s*:\s*(transparent|#fff(?:fff)?|#000(?:000)?)|font-size\s*:\s*0|"
    r"display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|"
    r"position\s*:\s*absolute[^;]*left\s*:\s*-9\d{3,})")
_EMPTY_LINK_RE = re.compile(r"\[[ \t\u200b-\u200d\ufeff]*\]\(\s*https?://[^)]+\)")


def _looks_like_instruction(decoded: str) -> bool:
    words = _IMPERATIVE_RE.findall(decoded)
    return len(set(w.lower() for w in words)) >= 2 or bool(
        re.search(r"(?i)ignore (previous|prior|all).*instructions", decoded))


def detect_hidden_instruction(rel: str, text: str) -> list:
    out = []
    if _ZERO_WIDTH_RE.search(text):
        n = len(_ZERO_WIDTH_RE.findall(text))
        out.append(_finding(HIDDEN_INSTRUCTION, 75, rel, None,
                            f"{n} zero-width/format characters",
                            "zero-width characters can hide instructions from human review"))
    for m in _COMMENT_RE.finditer(text):
        body = m.group(1)
        if len(body.strip()) >= 8 and _IMPERATIVE_RE.search(body):
            line = text.count("\n", 0, m.start()) + 1
            out.append(_finding(HIDDEN_INSTRUCTION, 75, rel, line,
                                "<!--" + body.strip()[:120] + "-->",
                                "HTML comment carries imperative language; comments are invisible when rendered"))
    if _INVISIBLE_CSS_RE.search(text) or 'aria-hidden="true"' in text:
        out.append(_finding(HIDDEN_INSTRUCTION, 75, rel, None, "invisible-content styling",
                            "CSS/ARIA hides content from the rendered page but not from the model"))
    for m in _EMPTY_LINK_RE.finditer(text):
        line = text.count("\n", 0, m.start()) + 1
        out.append(_finding(HIDDEN_INSTRUCTION, 75, rel, line, m.group(0)[:120],
                            "link with invisible anchor text points at a remote URL"))
    if rel.lower().endswith((".md", ".html", ".txt")):
        for m in _B64_TOKEN_RE.finditer(text):
            try:
                raw = base64.b64decode(m.group(1), validate=True)
            except (binascii.Error, ValueError):
                continue
            try:
                decoded = raw.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                continue
            if len(decoded) >= 12 and _looks_like_instruction(decoded):
                line = text.count("\n", 0, m.start()) + 1
                out.append(_finding(HIDDEN_INSTRUCTION, 75, rel, line,
                                    m.group(1)[:60] + "...",
                                    f"base64 blob decodes to instruction-like text: {decoded[:80]!r}"))
                break  # one finding per file is enough for the class
    return out


def detect_mcp_tool_poisoning(rel: str, text: str) -> list:
    out = []
    low = rel.lower()
    if low.endswith((".json", ".yaml", ".yml")) or "tool" in low or "manifest" in low:
        try:
            data = json.loads(text) if low.endswith(".json") else None
        except ValueError:
            data = None
        names = set()
        if isinstance(data, dict):
            tools = data.get("tools") or data.get("mcp_tools") or []
            if isinstance(data.get("name"), str):
                names.add(data["name"])
            for t in tools if isinstance(tools, list) else []:
                if isinstance(t, dict) and isinstance(t.get("name"), str):
                    names.add(t["name"])
                    desc = str(t.get("description", ""))
                    if re.search(r"(?i)\b(ignore|disregard|always|must|never reveal|do not (tell|reveal))\b", desc):
                        out.append(_finding(MCP_TOOL_POISONING, 75, rel, None, desc[:120],
                                            f"tool '{t['name']}' description carries directive language"))
        for m in re.finditer(r'"name"\s*:\s*"([^"]+)"', text):
            names.add(m.group(1))
        for name in names:
            if name in BUILTIN_TOOL_NAMES:
                out.append(_finding(MCP_TOOL_POISONING, 85, rel, None, name,
                                    f"declares a tool named '{name}', shadowing the built-in tool"))
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r"\s*(?:def|function|const|let|var)\s+([A-Za-z_][\w]*)", line)
        if m and m.group(1) in BUILTIN_TOOL_NAMES and low.endswith((".py", ".js", ".ts", ".sh")):
            out.append(_finding(MCP_TOOL_POISONING, 85, rel, i, line.strip(),
                                f"redefines '{m.group(1)}', shadowing the built-in tool"))
    return out


_INJECTION_RES = [
    (r"(?i)\bignore\s+(all\s+|any\s+|your\s+|the\s+)?(prior|previous)\s+instructions\b",
     "direct instruction override"),
    (r"(?i)\bdisregard\s+.*instructions\b", "direct instruction override"),
    (r"(?i)\bforget\s+(your|all)\s+instructions\b", "direct instruction override"),
    (r"(?i)^\s*(system|developer)\s*:\s*\S", "'system:'/'developer:' role marker in content"),
    (r"(?i)\bnew\s+instructions\s*:", "attempts to install new instructions"),
    (r"(?i)\breveal\s+your\s+(system\s+)?prompt\b", "asks the model to reveal its system prompt"),
    (r"(?i)\bdo\s+not\s+(tell|reveal|mention|disclose)\b.*\b(user|human)\b",
     "instructs the model to withhold from the user"),
    (r"(?i)\bpretend\s+(you\s+are|to\s+be)\b", "role-play jailbreak phrasing"),
    (r"(?i)\bjailbreak\b", "jailbreak phrasing"),
]


def detect_prompt_injection(rel: str, text: str) -> list:
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        for pat, what in _INJECTION_RES:
            if re.search(pat, line):
                out.append(_finding(PROMPT_INJECTION, 70, rel, i, line.strip(), what))
                break
    return out


_WEBHOOK_RE = re.compile(r"(?i)(discord\.com/api/webhooks|hooks\.slack\.com|webhook\.site|requestbin\.|ngrok\.io|pipedream\.net)")
_EXT_URL_RE = re.compile(r"https?://(?!localhost\b|127\.0\.0\.1\b)[\w.-]+")
_ENV_READ_RE = re.compile(r"(?i)(os\.environ|process\.env|getenv)")


def detect_data_exfiltration(rel: str, text: str) -> list:
    out = []
    low_lines = text.splitlines()
    for i, line in enumerate(low_lines, 1):
        if _WEBHOOK_RE.search(line):
            out.append(_finding(DATA_EXFILTRATION, 85, rel, i, line.strip()[:160],
                                "posts to a third-party webhook/catcher URL"))
        elif re.search(r"(?i)\bcurl\b[^|\n;]*(-X\s+POST|--data|--data-binary|-F\b)[^|\n;]*https?://", line):
            out.append(_finding(DATA_EXFILTRATION, 75, rel, i, line.strip()[:160],
                                "curl POSTs data to a remote URL"))
        elif re.search(r"requests\.(post|put)\s*\(\s*[\"']https?://(?!localhost|127\.0\.0\.1)", line):
            out.append(_finding(DATA_EXFILTRATION, 75, rel, i, line.strip()[:160],
                                "code POSTs to an external URL"))
        elif re.search(r"socket\.(create_connection|connect)\s*\(\s*\([\"'](?!127\.|localhost)", line):
            out.append(_finding(DATA_EXFILTRATION, 80, rel, i, line.strip()[:160],
                                "opens a raw socket to an external host"))
    if _ENV_READ_RE.search(text) and _EXT_URL_RE.search(text):
        already = any(f["code"] == DATA_EXFILTRATION for f in out)
        if not already:
            out.append(_finding(DATA_EXFILTRATION, 70, rel, None, "env read + external URL in one file",
                                "the bundle reads environment data and references an external URL; "
                                "review whether local data leaves the machine"))
    return out


_PERSIST_RES = [
    (r"(?i)\bcrontab\b|/etc/cron", "installs a cron job"),
    (r"LaunchAgents|LaunchDaemons|RunAtLoad", "installs a macOS launchd job"),
    (r"systemctl\s+(enable|daemon-reload)|\.service\b.*\[Install\]", "installs a systemd unit"),
    (r"(?i)(>>|>\s*)(~|\$HOME)/\.(bashrc|zshrc|profile|bash_profile)", "appends to a shell startup file"),
    (r"(?i)HKEY_[A-Z_]+\\.*\\Run", "writes a Windows Run registry key"),
    (r"\.git/hooks/", "installs a git hook"),
    (r"(?i)\bschtasks\b.*/(create|change)", "creates a Windows scheduled task"),
    (r"(?i)~?/\.config/autostart/", "installs a desktop autostart entry"),
]


def detect_persistence(rel: str, text: str) -> list:
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        for pat, what in _PERSIST_RES:
            if re.search(pat, line):
                out.append(_finding(PERSISTENCE, 70, rel, i, line.strip()[:160], what))
                break
    return out


_URL_DEP_RE = re.compile(r"(?i)https?://\S+\.(?:tar\.gz|tgz|zip|whl)\b|git\+https?://\S+")
_PIP_URL_RE = re.compile(r"(?i)\bpip\s+install\b[^|\n;]*https?://")
_NPM_URL_RE = re.compile(r"(?i)\bnpm\s+(?:i|install)\b[^|\n;]*https?://")


def detect_risky_dependency(rel: str, text: str) -> list:
    out = []
    low = rel.lower()
    is_dep_file = low.endswith(("requirements.txt", "requirements.in", "package.json",
                                "pyproject.toml", "setup.py", "setup.cfg", "Pipfile",
                                "yarn.lock", "package-lock.json", "Gemfile"))
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#") or s.startswith("//"):
            continue
        if _URL_DEP_RE.search(s) or _PIP_URL_RE.search(s) or _NPM_URL_RE.search(s):
            out.append(_finding(RISKY_DEPENDENCY, 70, rel, i, s[:160],
                                "dependency fetched from a remote URL/tarball instead of a package index"))
        elif is_dep_file and re.search(r'["\']?\w[\w.-]*["\']?\s*[:=]\s*["\']?\*["\']?', s) \
                and "version" not in s.lower():
            out.append(_finding(RISKY_DEPENDENCY, 25, rel, i, s[:160],
                                "unpinned dependency ('*'): any future version is accepted silently"))
    return out


_DETECTORS = (detect_credential_access, detect_remote_script_fetch,
              detect_hidden_instruction, detect_mcp_tool_poisoning,
              detect_prompt_injection, detect_data_exfiltration,
              detect_persistence, detect_risky_dependency)


def scan_bundle(bundle: Path) -> tuple[list, dict]:
    """Run all nine detectors. Returns (findings, skill_md_frontmatter)."""
    files = list(_iter_scannable(bundle))
    skill_md = ""
    for rel, text, _reasons, _head, _size in files:
        if rel.lower() == "skill.md" and text is not None:
            skill_md = text
            break
    findings: list = []
    for rel, text, reasons, head, size in files:
        if text is not None:
            for det in _DETECTORS:
                if det is detect_credential_access:
                    findings.extend(det(rel, text, skill_md))
                else:
                    findings.extend(det(rel, text))
        if reasons:
            findings.extend(detect_unscanned_file(rel, reasons, head, size))
    return findings, _frontmatter(skill_md)


def score_findings(findings: list) -> tuple[int, dict, list]:
    """Per-class contribution = highest finding weight in that class; the score
    is the clamped sum. Returns (score, class_scores, reason_codes)."""
    class_scores = {c: 0 for c in ATTACK_CLASSES}
    for f in findings:
        class_scores[f["code"]] = max(class_scores[f["code"]], f["weight"])
    score = min(100, sum(class_scores.values()))
    codes = [c for c in ATTACK_CLASSES if class_scores[c] > 0]
    return score, class_scores, codes


# ---------------------------------------------------------------------------
# verdicts
# ---------------------------------------------------------------------------

def make_verdict(name: str, version: str, findings: list, manifest: dict,
                 reject_at: int = DEFAULT_REJECT_AT,
                 warn_at: int = DEFAULT_WARN_AT) -> dict:
    score, class_scores, codes = score_findings(findings)
    if score >= reject_at:
        decision, state = "REJECT", "blocked"
    elif score >= warn_at:
        decision, state = "ACCEPT_WITH_WARNINGS", "warnings"
    else:
        decision, state = "ACCEPT", "ok"
    reasons = [{"state": state, "code": f["code"], "message": f["detail"],
                "file": f["file"], "line": f["line"], "weight": f["weight"]}
               for f in sorted(findings, key=lambda f: (-f["weight"], f["file"] or ""))]
    return {"decision": decision, "state": state, "skill": name, "version": version,
            "bundle_sha256": _bundle_digest(manifest), "score": score,
            "thresholds": {"warn_at": warn_at, "reject_at": reject_at},
            "reason_codes": codes, "class_scores": class_scores, "reasons": reasons,
            "scanned_at": dt.datetime.now(dt.timezone.utc).isoformat()}


def invalid_verdict(name: str, code: str, message: str) -> dict:
    return {"decision": "REJECT", "state": "invalid", "skill": name, "version": None,
            "bundle_sha256": None, "score": 100,
            "thresholds": {"warn_at": DEFAULT_WARN_AT, "reject_at": DEFAULT_REJECT_AT},
            "reason_codes": [code], "class_scores": {},
            "reasons": [{"state": "invalid", "code": code, "message": message,
                         "file": None, "line": None, "weight": 100}],
            "scanned_at": dt.datetime.now(dt.timezone.utc).isoformat()}


# ---------------------------------------------------------------------------
# admission store: signed, chained receipts + a current-verdict index
# ---------------------------------------------------------------------------

def _receipt_input(receipt: dict) -> bytes:
    body = {k: v for k, v in receipt.items() if k != "sig"}
    return ADMISSION_SIG_DOMAIN.encode() + b"\n" + sc.canonical_json(body)


def _receipt_digest(receipt: dict) -> str:
    return hashlib.sha256(sc.canonical_json(
        {k: v for k, v in receipt.items() if k != "sig"})).hexdigest()


@contextlib.contextmanager
def _store_lock(store: Path):
    store.parent.mkdir(parents=True, exist_ok=True)
    lock = store.with_name(store.name + ".lock")
    fh = open(lock, "a+")
    try:
        try:
            import fcntl
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        except ImportError:  # pragma: no cover - Windows: best effort
            pass
        yield
    finally:
        fh.close()


def _load_store(store: Path) -> dict:
    try:
        data = json.loads(store.read_text())
    except (OSError, ValueError):
        return {"v": 1, "skills": {}, "receipts": []}
    if not isinstance(data, dict) or not isinstance(data.get("receipts"), list):
        return {"v": 1, "skills": {}, "receipts": []}
    data.setdefault("skills", {})
    return data


def _save_store(store: Path, data: dict) -> None:
    tmp = store.with_name(f".{store.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(json.dumps(data, indent=2, sort_keys=True) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, store)


def verify_chain(data: dict) -> list:
    """Return a list of chain problems (empty = intact)."""
    problems = []
    prev = None
    for i, r in enumerate(data.get("receipts", []), 1):
        if not isinstance(r, dict):
            problems.append(f"receipt {i}: not an object")
            continue
        if r.get("seq") != i:
            problems.append(f"receipt {i}: seq is {r.get('seq')}")
        want_prev = _receipt_digest(prev) if prev is not None else None
        if r.get("prev") != want_prev:
            problems.append(f"receipt {i}: prev does not match the previous receipt")
        prev = r
    return problems


def verify_receipt_signatures(data: dict, registry: dict | None) -> list:
    """Return per-receipt signature results: {'seq', 'signer', 'kid', 'valid'}."""
    out = []
    for r in data.get("receipts", []):
        if not isinstance(r, dict):
            continue
        sig = r.get("sig")
        key = sc.find_key(registry, r.get("signer"), r.get("kid")) if registry else None
        valid = False
        if key is not None and isinstance(sig, str):
            try:
                valid = sc.verify_bytes(key, _receipt_input(r), sc.unb64u(sig))
            except Exception:
                valid = False
        out.append({"seq": r.get("seq"), "signer": r.get("signer"), "kid": r.get("kid"),
                    "valid": valid})
    return out


def append_receipt(store: Path, key: dict, verdict: dict, manifest: dict,
                   policy: dict) -> dict:
    """Chain (seq/prev), sign and persist an admission receipt; update the
    skill's current-verdict index entry. Returns the receipt."""
    with contextlib.ExitStack() as stack:
        # enter the file lock manually (it is a generator)
        lock = _store_lock(store)
        stack.enter_context(lock)
        data = _load_store(store)
        problems = verify_chain(data)
        if problems:
            raise SystemExit(f"admission store is corrupt, refusing to append: {problems[0]}")
        prev = data["receipts"][-1] if data["receipts"] else None
        receipt = {
            "v": 1,
            "seq": len(data["receipts"]) + 1,
            "prev": _receipt_digest(prev) if prev is not None else None,
            "kind": "skill-admission",
            "skill": verdict["skill"],
            "version": verdict["version"],
            "bundle_sha256": verdict["bundle_sha256"],
            "manifest": manifest,
            "decision": verdict["decision"],
            "score": verdict["score"],
            "reason_codes": verdict["reason_codes"],
            "reasons": verdict["reasons"],
            "thresholds": verdict["thresholds"],
            "admitted_at": verdict["scanned_at"],
            "signer": key.get("agent"),
            "kid": key.get("kid"),
        }
        receipt["sig"] = sc.b64u(sc.sign_bytes(key["_secret"], _receipt_input(receipt)))
        data["receipts"].append(receipt)
        data["skills"][verdict["skill"]] = {
            "version": verdict["version"],
            "bundle_sha256": verdict["bundle_sha256"],
            "manifest": manifest,
            "decision": verdict["decision"],
            "score": verdict["score"],
            "reason_codes": verdict["reason_codes"],
            "reasons": verdict["reasons"],
            "receipt_seq": receipt["seq"],
            "admitted_at": verdict["scanned_at"],
            "policy": policy,
        }
        _save_store(store, data)
        return receipt


# ---------------------------------------------------------------------------
# public API (importable; the CLI below is one caller)
# ---------------------------------------------------------------------------

def _skill_identity(bundle: Path, front: dict, name_arg: str | None) -> tuple[str, str]:
    name = name_arg or front.get("name") or bundle.name
    version = str(front.get("version") or "unversioned")
    pkg = bundle / "package.json"
    if version == "unversioned" and pkg.is_file():
        with contextlib.suppress(Exception):
            version = str(json.loads(pkg.read_text()).get("version") or "unversioned")
    return str(name), version


def admit_skill(bundle: str | Path, key: dict, store: str | Path,
                name: str | None = None, reject_at: int = DEFAULT_REJECT_AT,
                warn_at: int = DEFAULT_WARN_AT,
                ignore: list | None = None) -> tuple[dict, dict]:
    """Scan a skill bundle and record the signed admission receipt.

    Returns (verdict, receipt). Raises SystemExit on unusable input
    (missing SKILL.md, unreadable store, corrupt chain)."""
    bundle = Path(bundle)
    if not bundle.is_dir():
        raise SystemExit(f"bundle is not a directory: {bundle}")
    skill_md = bundle / "SKILL.md"
    if not skill_md.is_file():
        v = invalid_verdict(name or bundle.name, "skill_manifest_missing",
                            f"{bundle} has no SKILL.md; a skill bundle must describe itself")
        policy = {"reject_at": reject_at, "warn_at": warn_at, "ignore": ignore or []}
        receipt = append_receipt(Path(store), key, v, {}, policy)
        return v, receipt
    findings, front = scan_bundle(bundle)
    if ignore:
        findings = [f for f in findings if f["code"] not in set(ignore)]
    manifest = _manifest(bundle)
    skill_name, version = _skill_identity(bundle, front, name)
    verdict = make_verdict(skill_name, version, findings, manifest, reject_at, warn_at)
    policy = {"reject_at": reject_at, "warn_at": warn_at, "ignore": ignore or []}
    receipt = append_receipt(Path(store), key, verdict, manifest, policy)
    verdict["receipt_seq"] = receipt["seq"]
    return verdict, receipt


def check_freshness(entry: dict, bundle: str | Path) -> dict:
    """Re-hash the bundle on disk and compare with the admitted manifest.

    Returns {'fresh': bool, 'changed': [...], 'code': ...}."""
    current = _manifest(Path(bundle))
    stored = entry.get("manifest") or {}
    changed = sorted({p for p in set(current) | set(stored) if current.get(p) != stored.get(p)})
    fresh = not changed
    return {"fresh": fresh, "changed": changed,
            "code": None if fresh else "admission_stale",
            "detail": None if fresh else
            f"{len(changed)} file(s) changed since admission; re-scan to admit the new bytes"}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print_verdict(verdict: dict) -> None:
    print(json.dumps(verdict, indent=2))


def cmd_admit(a) -> int:
    policy = {}
    if a.policy:
        try:
            policy = json.loads(Path(a.policy).read_text())
        except (OSError, ValueError) as e:
            raise SystemExit(f"cannot read policy file: {e}") from None
    reject_at = int(policy.get("reject_at", a.reject_at or DEFAULT_REJECT_AT))
    warn_at = int(policy.get("warn_at", a.warn_at or DEFAULT_WARN_AT))
    if not (0 <= warn_at <= reject_at <= 100):
        raise SystemExit("policy must satisfy 0 <= warn_at <= reject_at <= 100")
    try:
        key = load_key(a.key)
    except SystemExit as e:
        raise e
    except Exception as e:
        raise SystemExit(f"cannot load signing key {a.key}: {e}") from None
    verdict, receipt = admit_skill(
        a.bundle, key, a.store, name=a.name, reject_at=reject_at, warn_at=warn_at,
        ignore=(policy.get("ignore") or []) + (a.ignore or []))
    _print_verdict(verdict)
    sys.stderr.write(f"receipt seq {receipt['seq']} recorded for '{verdict['skill']}' "
                     f"({verdict['decision']}, score {verdict['score']})\n")
    return 0 if verdict["decision"] != "REJECT" else 2


def _latest_skill_receipt(data: dict, name: str) -> dict | None:
    """The highest-seq skill-admission receipt for this skill (the latest word
    the signer published), regardless of what the unsigned index claims."""
    best = None
    for r in data.get("receipts", []):
        if (isinstance(r, dict) and r.get("kind") == "skill-admission"
                and r.get("skill") == name
                and (best is None or (r.get("seq") or 0) > (best.get("seq") or 0))):
            best = r
    return best


# Fields the unsigned index must agree with the latest signed receipt on.
_INDEX_CHECK_FIELDS = ("decision", "score", "version", "bundle_sha256",
                       "receipt_seq", "reason_codes")


def cmd_status(a) -> int:
    # The verdict is only trustworthy when the receipt signature verifies, so
    # the registry is mandatory: without it, status cannot tell a real verdict
    # from a forged one.
    if not a.registry:
        raise SystemExit("status requires --registry: the verdict comes from the "
                         "signed receipt, and the signature must verify")
    store = Path(a.store)
    with contextlib.ExitStack() as stack:
        stack.enter_context(_store_lock(store))
        data = _load_store(store)
        receipt = _latest_skill_receipt(data, a.name)
        if receipt is None:
            raise SystemExit(f"no admission receipt for skill '{a.name}' in {store}")
        try:
            registry = json.loads(Path(a.registry).read_text())
        except (OSError, ValueError) as e:
            raise SystemExit(f"cannot read registry {a.registry}: {e}") from None
        problems = verify_chain(data)
        sigs = {s["seq"]: s for s in verify_receipt_signatures(data, registry)}
        signature_valid = bool(sigs.get(receipt.get("seq"), {}).get("valid"))
        entry = data["skills"].get(a.name)
        index_mismatch: list = []
        if entry is None:
            index_mismatch = ["index entry missing"]
        else:
            for field in _INDEX_CHECK_FIELDS:
                # the index calls it receipt_seq; the receipt calls it seq
                got = entry.get(field)
                want = receipt.get("seq") if field == "receipt_seq" else receipt.get(field)
                if got != want:
                    index_mismatch.append(field)
        report = {
            "skill": a.name,
            "decision": receipt["decision"],
            "score": receipt["score"],
            "version": receipt["version"],
            "reason_codes": receipt["reason_codes"],
            "findings": receipt["reasons"],
            "admitted_at": receipt["admitted_at"],
            "receipt": ({"seq": receipt.get("seq"), "signer": receipt.get("signer"),
                         "kid": receipt.get("kid"),
                         "bundle_sha256": receipt.get("bundle_sha256"),
                         "sig": receipt.get("sig"),
                         "signature_valid": signature_valid}),
            "index_mismatch": index_mismatch or False,
            "chain_intact": not problems,
        }
        if problems:
            report["chain_problems"] = problems
        if a.bundle:
            report["freshness"] = check_freshness(receipt, a.bundle)
    _print_verdict(report)
    if problems or not signature_valid or index_mismatch:
        return 3  # integrity failure: chain, signature, or index tampering
    if receipt["decision"] == "REJECT":
        return 2
    if a.bundle and report.get("freshness") and not report["freshness"]["fresh"]:
        return 2
    return 0


def cmd_verify(a) -> int:
    store = Path(a.store)
    with contextlib.ExitStack() as stack:
        stack.enter_context(_store_lock(store))
        data = _load_store(store)
        problems = verify_chain(data)
        registry = json.loads(Path(a.registry).read_text()) if a.registry else None
        sigs = verify_receipt_signatures(data, registry) if registry else []
        report = {"store": str(store), "receipts": len(data["receipts"]),
                  "chain_intact": not problems, "chain_problems": problems,
                  "signatures": sigs if registry else "registry not given; signatures not checked"}
    _print_verdict(report)
    bad = problems or [s for s in sigs if not s["valid"]]
    return 2 if bad else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Synthe skill admission scanning")
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("admit", help="scan a skill bundle and record a signed admission receipt")
    d.add_argument("bundle", help="directory holding the skill (SKILL.md at top level)")
    d.add_argument("--key", required=True, help="signing key file (synthe-sign keygen output)")
    d.add_argument("--store", default="synthe-admissions.json",
                   help="admission store file (default ./synthe-admissions.json)")
    d.add_argument("--name", help="skill name (default: SKILL.md frontmatter `name:`, else the directory name)")
    d.add_argument("--policy", help="JSON policy file: {reject_at, warn_at, ignore[]}")
    d.add_argument("--reject-at", type=int, help="reject when score >= this (default 70)")
    d.add_argument("--warn-at", type=int, help="ACCEPT_WITH_WARNINGS when score >= this (default 40)")
    d.add_argument("--ignore", action="append", help="attack-class code to skip (repeatable)")

    s = sub.add_parser("status", help="show a skill's verdict from its latest signed receipt")
    s.add_argument("name")
    s.add_argument("--store", default="synthe-admissions.json")
    s.add_argument("--bundle", help="re-hash this directory; report whether the receipt still covers it")
    s.add_argument("--registry", required=True,
                   help="REQUIRED: verify the receipt signature against this registry. "
                        "Exit 0 = verified ACCEPT, 2 = verified REJECT or stale bundle, "
                        "3 = broken chain, bad signature, or index/receipt mismatch.")

    v = sub.add_parser("verify", help="offline audit of the admission receipt chain")
    v.add_argument("--store", default="synthe-admissions.json")
    v.add_argument("--registry", help="verify receipt signatures against this registry")

    a = ap.parse_args(argv)
    return {"admit": cmd_admit, "status": cmd_status, "verify": cmd_verify}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
