#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Lane grants from your own terminal, in one command (behind `synthe-task grant|grants|revoke-grant`).

  synthe-task grant [--branch 'agent/*'] [--paths 'src/**,tests/**'] [--uses 50] [--until 7d]
                    [--remote origin] [--agent openclaw] [--delegate ID] [--brief TEXT] [--passphrase]
  synthe-task grants [--all]
  synthe-task revoke-grant ID

A lane grant (synthe_lane_templates.py) lets pushes inside its limits go out without asking you each
time: one agent, git_push only, a branch pattern, the files it may touch, a number of uses, an expiry.
`grant` fills what it can from your setup (remote, agent, branches, allowed paths), shows what you are
about to allow in plain words, asks, then signs with your key (Touch ID if you enrolled one, otherwise
your passphrase) and hands it to the broker. The broker computes the lineage digests the grant is
signed against and re-checks everything at every push; this file only builds, shows and signs.

By default a lane has no use limit and no expiry: it stays open until you revoke it. --uses and --until
cap it if you want one. (The grant schema requires both, so "none" is the largest values the broker
accepts: 10000 uses and the year 9999.) What a lane never covers are the stops: main, master and patterns
that reach them, and the policy's forbidden paths.

Only you can run it: it needs a terminal you are typing in, and the signature needs your passphrase or
your finger. There is no --yes. An unattended lane trades review for speed within its limits: while it
is open, nobody reads each push before it goes out (the receipt still records it).
"""
from __future__ import annotations

import argparse
import datetime as dt
import re
import secrets
import shlex
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import handoff_check as hc  # noqa: E402
import synthe_client as scl  # noqa: E402
import synthe_lane_templates as lanes  # noqa: E402
import synthe_sign as ss  # noqa: E402
import synthe_touchid as touchid  # noqa: E402
import synthe_ui as sui  # noqa: E402

UNLIMITED_USES = 10000      # the schema needs a number; this is the most the broker accepts (lanes.validate)
NO_EXPIRY = dt.datetime(9999, 1, 1, tzinfo=dt.timezone.utc)   # ...and a date: no upper bound is checked
MIN_MINUTES = 5
REFUSED_BRANCHES = ("main", "master")   # also anything that matches them: '*', '**', 'ma*'
RENEW_WITHIN = dt.timedelta(hours=24)
RENEW_USES = 0.10           # flag a grant with less than this fraction of its uses left
INACTIVE = {
    "template_expired": "expired",
    "template_revoked": "revoked",
    "template_exhausted": "used up",
    "template_stale": "stale (the policy, approvers or config changed since you signed it)",
}
EXPLAIN = {
    "template_scope": "lane grants aren't switched on for this agent on this broker",
    "approver_not_trusted": "your approver identity isn't trusted for this agent in the broker's registry",
    "template_stale": "the broker's policy, approvers or config changed while you were signing; try again",
    "template_signature_invalid": "the broker doesn't recognise the signature (is this key registered with it? "
                                  "after enrolling Touch ID the admin step must run first)",
    "delegate_invalid": "the delegate isn't a registered model approver (see docs/COMMIT.md)",
    "template_malformed": "the broker found the grant malformed",
}


# ---- reading what you asked for --------------------------------------------------------------

def _csv(text) -> list:
    return [x.strip() for x in re.split(r"[,\n]", text or "") if x.strip()]


def _join(items: list) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def unlimited_uses(t: dict) -> bool:
    return t["max_uses"] >= UNLIMITED_USES


def no_expiry(end: dt.datetime) -> bool:
    return end >= NO_EXPIRY


def parse_until(text: str, now: dt.datetime, tz=None) -> dt.datetime:
    """When the grant ends: a length (90m, 12h, 7d, 2w) or a date/time (2026-10-30, 2026-10-30T17:00, local
    time unless it names a zone). Not sooner than MIN_MINUTES; there is no upper bound."""
    text = (text or "").strip()
    m = re.fullmatch(r"(\d{1,5})\s*([mhdw])", text.lower())
    if m:
        unit = {"m": "minutes", "h": "hours", "d": "days", "w": "weeks"}[m.group(2)]
        end = now + dt.timedelta(**{unit: int(m.group(1))})
    else:
        try:
            end = dt.datetime.fromisoformat(text)
        except ValueError:
            raise SystemExit(f"--until {text!r}: say how long (90m, 12h, 7d, 2w) or give a date (2026-10-30)")
        if len(text) == 10:  # a bare date means the end of that day
            end = end.replace(hour=23, minute=59, second=59)
        if end.tzinfo is None:
            end = end.replace(tzinfo=tz) if tz else end.astimezone()
    try:
        end = end.astimezone(dt.timezone.utc).replace(microsecond=0)
    except OverflowError:
        raise SystemExit(f"--until {text!r} is past the year 9999; leave --until out for no expiry")
    if end < now + dt.timedelta(minutes=MIN_MINUTES):
        raise SystemExit(f"--until {text!r} is too soon: a grant lasts at least {MIN_MINUTES} minutes")
    return min(end, NO_EXPIRY)


def _sample(pattern: str) -> str:
    """One path a glob matches, with the widest wildcard reading: to ask whether a pattern stays inside another."""
    return re.sub(r"\*\*/|\*\*|\*|\?", lambda m: {"**/": "x/y/", "**": "x/y", "*": "x", "?": "x"}[m.group()], pattern)


def _inside(patterns: list, wanted: str) -> bool:
    return any(hc.glob_match(p, _sample(wanted)) for p in patterns)


def check_branch(pattern: str, allowed: list) -> str:
    pattern = (pattern or "").strip()
    if not pattern or re.search(r"\s", pattern) or pattern.startswith("/") or ".." in pattern.split("/"):
        raise SystemExit(f"--branch {pattern!r}: give a branch pattern such as 'agent/*'")
    if pattern in REFUSED_BRANCHES or any(hc.glob_match(pattern, b) for b in REFUSED_BRANCHES):
        raise SystemExit(f"--branch {pattern!r}: a lane covers the agent's own branches, never main or master "
                         f"(or a pattern that reaches them, like '*'). A human merges; try 'agent/*'")
    if allowed and not _inside(allowed, pattern):
        raise SystemExit(f"--branch {pattern!r} is outside the branches the broker may push "
                         f"({', '.join(allowed)}); a push there would be refused")
    return pattern


def check_paths(paths: list, policy: dict) -> list:
    """Each path glob must stay inside what the receiver's policy allows and clear of what it forbids: a grant
    can only narrow the policy, so anything else could never be used (the broker would refuse the push)."""
    if not paths:
        raise SystemExit("--paths: give at least one glob, e.g. 'src/**'")
    if len(paths) > 100:
        raise SystemExit("--paths: at most 100 globs")
    allowed, forbidden = policy.get("allowed_paths") or [], policy.get("forbidden_paths") or []
    for p in paths:
        if p.startswith("/") or ".." in p.split("/") or "\\" in p:
            raise SystemExit(f"--paths {p!r}: paths are relative to the repo root, with no '..' or backslashes")
        if _inside(forbidden, p):
            raise SystemExit(f"--paths {p!r} is on the agent's forbidden list ({', '.join(forbidden)}): the broker "
                             f"refuses those files whatever a grant says")
        if allowed and not _inside(allowed, p):
            raise SystemExit(f"--paths {p!r} is outside what the agent's policy allows ({', '.join(allowed)}); a "
                             f"push touching it would be refused. Use paths inside that, or change the policy first")
    return paths


def _local(when: dt.datetime, tz=None) -> str:
    d = when.astimezone(tz) if tz else when.astimezone()
    return f"{d:%a %b} {d.day} {d:%H:%M %Z}".strip()


def summary(body: dict, policy: dict | None = None, tz=None) -> str:
    """What this grant allows, in plain words, for the person about to sign it."""
    n, until = body["max_uses"], hc.parse_ts(body["expires_at"])
    where = body["params"]["branch_pattern"] + ("" if body["params"]["remote"] == "origin"
                                                  else f" on {body['params']['remote']}")
    limit = "with no limit on pushes" if unlimited_uses(body) else "once" if n == 1 else f"up to {n} times"
    lines = [f"Agent {body['receiver']} may push to {where} changing {_join(body['path_scope'])}, {limit}, "
             + ("with no expiry." if no_expiry(until) else f"until {_local(until, tz)}."),
             "Pushes to other branches still ask you. A push on this branch that touches other files is refused, "
             "not asked about."]
    if "delegate" in body:
        lines.append(f"Each push in the lane is reviewed by {body['delegate']} instead of you; it can send a push "
                     f"back to you. It may approve what a fooled reviewer would: the limits above are the bound.")
    else:
        lines.append("Inside the lane nobody reviews each push before it goes out: Synthe still checks the branch "
                     "and files and signs a receipt for every push, but you are not asked.")
    if unlimited_uses(body) and no_expiry(until):
        lines.append(f"With no limit and no expiry this is a standing permission: it stays open until you close it "
                     f"(synthe-task revoke-grant {body['template_id']}).")
    never = (policy or {}).get("forbidden_paths") or []
    if never:
        lines.append(f"Never, whatever this says: {', '.join(never)}.")
    return "\n".join(lines)


# ---- building, signing, submitting -----------------------------------------------------------

def plan(s: dict, *, client, branch: str, paths: list, uses: int | None = None, until: str | None = None,
         remote: str = "origin",
         receiver: str | None = None, delegate: str | None = None, brief: str | None = None,
         now: dt.datetime | None = None, template_id: str | None = None, tz=None) -> tuple[dict, str]:
    """The unsigned grant and its summary, after every check that can be made before you sign. `s` is
    synthe_task.setup_of(home). The broker supplies the lineage digests (op lane_template_draft)."""
    now = (now or dt.datetime.now(dt.timezone.utc)).replace(microsecond=0)
    receiver = receiver or s["receiver"]
    if receiver != s["receiver"]:
        raise SystemExit(f"--agent {receiver!r}: this setup has one agent, {s['receiver']!r}")
    uses = UNLIMITED_USES if uses is None else uses
    if not isinstance(uses, int) or isinstance(uses, bool) or not 1 <= uses <= UNLIMITED_USES:
        raise SystemExit(f"--uses: between 1 and {UNLIMITED_USES} (leave it out for no limit)")
    if brief is not None and (not brief.strip() or len(brief) > lanes.MAX_BRIEF):
        raise SystemExit(f"--brief: say something, in up to {lanes.MAX_BRIEF} characters")
    remotes = {"origin": s["remote"].get("branches") or []}
    if remote not in remotes:
        remotes = {remote: (client.call("hello").get("remotes") or {}).get(remote, {}).get("branches")}
        if remotes[remote] is None:
            raise SystemExit(f"--remote {remote!r}: the broker has no such remote")
    branch = check_branch(branch, remotes[remote])
    paths = check_paths(paths, s["policy"])
    end = parse_until(until, now, tz) if until is not None else NO_EXPIRY
    if receiver not in (client.call("lane_templates").get("enabled_receivers") or []):
        raise SystemExit(f"lane grants aren't switched on for {receiver} on this broker. Setups from before they "
                         f"existed need \"lane_templates\": {{\"receivers\": [\"{receiver}\"]}} in "
                         f"{s.get('broker_config') or 'the broker config'}, then a broker restart")
    body = {"template_id": template_id or f"lane-{now:%Y%m%d}-{secrets.token_hex(3)}", "receiver": receiver,
            "tool": "git_push", "params": {"remote": remote, "branch_pattern": branch}, "path_scope": paths,
            "max_uses": uses, "expires_at": end.strftime("%Y-%m-%dT%H:%M:%SZ")}
    if delegate:
        body["delegate"] = delegate
    if brief:
        body["brief"] = brief
    try:
        body["lineage"] = client.call("lane_template_draft", receiver=receiver)["lineage"]
    except scl.BrokerError as e:
        raise SystemExit(f"the broker can't prepare a grant: {e.code}: {e.message}")
    return body, summary(body, s["policy"], tz)


def unlock_key(home: Path, sender: str, reason: str, passphrase: bool = False, prompt=ss.prompt_passphrase) -> dict:
    """Your approver key, the way synthe-approve opens it: Touch ID when you enrolled one (its prompt shows
    `reason`), otherwise the passphrase key. Typed or touched by you, in your terminal; never by an agent."""
    tid = touchid.key_path(home)
    try:
        if not passphrase and tid.is_file():
            key = touchid.signing_key(tid, reason)
        else:
            key = ss.load_key(str(home / "approver.key.json"), require_encrypted=True, prompt=prompt)
    except touchid.TouchIDError as e:
        raise SystemExit(f"not signed: {e} (--passphrase uses your passphrase key instead)")
    if key.get("agent") != sender:
        raise SystemExit(f"the approver key belongs to {key.get('agent')!r}, not {sender!r}")
    return key


def submit(client, body: dict, key: dict) -> dict:
    """Sign with an unlocked key and give the grant to the broker; the broker re-validates all of it."""
    try:
        signed = lanes.sign(body, key)
    except touchid.TouchIDError as e:
        raise SystemExit(f"not signed: {e}")
    try:
        return client.call("submit_lane_template", template=signed)
    except scl.BrokerError as e:
        raise SystemExit(f"the broker refused the grant: {e.code}: {EXPLAIN.get(e.code, e.message)}")


def _terminal() -> bool:
    return sys.stdin.isatty() and sys.stderr.isatty()


def _yes(question: str) -> bool:
    try:
        answer = input(question).strip().lower()
    except EOFError:
        return False
    return answer in ("y", "yes") or (answer == "" and "[Y/n]" in question)


def issue(home: Path, *, client=None, key=None, confirm=None, out=print, passphrase: bool = False,
          question: str = "Sign this lane grant? [y/N] ", **spec):
    """Build, show, ask, sign and submit one grant. Returns the broker's answer, or None if you said no."""
    import synthe_task as stk
    confirm = confirm or _yes
    s = stk.setup_of(home)
    client = client or scl.BrokerClient(s["broker"])
    body, text = plan(s, client=client, **spec)
    out("\n" + text + "\n")
    if not confirm(question):
        out("Nothing signed. Pushes keep asking you.")
        return None
    key = key or unlock_key(home, s["sender"], text.splitlines()[0], passphrase)
    result = submit(client, body, key)
    end = hc.parse_ts(body["expires_at"])
    out(f"Lane open: {body['template_id']} ({'no use limit' if unlimited_uses(body) else str(body['max_uses']) + ' uses'}, "
        f"{'no expiry' if no_expiry(end) else 'until ' + _local(end)}).\n"
        f"See it with synthe-task grants; close it any time with synthe-task revoke-grant {body['template_id']}.")
    return result


# ---- listing, renewing, revoking -------------------------------------------------------------

def _left(delta: dt.timedelta) -> str:
    mins = int(delta.total_seconds() // 60)
    if mins <= 0:
        return "now"
    d, rest = divmod(mins, 1440)
    h, m = divmod(rest, 60)
    return f"{d}d {h}h" if d else f"{h}h {m}m" if h else f"{m}m"


def renew_command(t: dict) -> str:
    cmd = ["synthe-task", "grant", "--branch", t["params"]["branch_pattern"], "--paths", ",".join(t["path_scope"])]
    if not unlimited_uses(t):
        cmd += ["--uses", str(t["max_uses"])]
    if not no_expiry(hc.parse_ts(t["expires_at"])):
        cmd += ["--until", "7d"]
    if t["params"]["remote"] != "origin":
        cmd += ["--remote", t["params"]["remote"]]
    if t.get("delegate"):
        cmd += ["--delegate", t["delegate"]]
    if t.get("brief") and len(t["brief"]) <= 200:
        cmd += ["--brief", t["brief"]]
    return shlex.join(cmd) + ("   (add your --brief again)" if t.get("brief") and len(t["brief"]) > 200 else "")


def list_grants(client, now: dt.datetime | None = None) -> list:
    """Every grant the broker holds, newest expiry first, each with `left` (time to expiry), `hints` (why to
    renew it: under 24 hours left, or under 10% of its uses) and `renew` (the command that makes a fresh one)."""
    now = now or dt.datetime.now(dt.timezone.utc)
    rows = []
    for t in client.call("lane_templates").get("templates") or []:
        end = hc.parse_ts(t["expires_at"])
        hints = []
        if t["status"] == "active":   # a lane with no limit has nothing to run out of
            if not no_expiry(end) and end - now <= RENEW_WITHIN:
                hints.append(f"expires in {_left(end - now)}")
            if not unlimited_uses(t) and t["uses_left"] < RENEW_USES * t["max_uses"]:
                hints.append(f"only {t['uses_left']} of {t['max_uses']} uses left")
        rows.append({**t, "left": end - now, "hints": hints, "renew": renew_command(t)})
    return sorted(rows, key=lambda r: r["left"], reverse=True)


def render_grants(rows: list, show_all: bool = False, ui=None, tz=None) -> str:
    ui = ui or sui.UI()
    shown = [r for r in rows if show_all or r["status"] == "active"]
    hidden = len(rows) - len(shown)
    if not shown:
        out = ["No open lanes. Every push asks you. Open one: synthe-task grant"]
    else:
        out = []
        for r in shown:
            state = "open" if r["status"] == "active" else INACTIVE.get(r["status"], r["status"])
            who = f", reviewed by {r['delegate']}" if r.get("delegate") else ", no per-push review"
            out.append(f"{ui.c(r['template_id'], 'brand', bold=True)}  {ui.c(state, 'ok' if r['status'] == 'active' else 'muted')}")
            out.append(f"  {r['receiver']} may push to {r['params']['branch_pattern']} changing "
                       f"{', '.join(r['path_scope'])}{who}")
            end = hc.parse_ts(r["expires_at"])
            until = "" if no_expiry(end) else _local(end, tz)
            uses = "no use limit" if unlimited_uses(r) else f"{r['uses_left']} of {r['max_uses']} uses left"
            out.append(f"  {uses}, " + ("no expiry (open until you revoke it)" if no_expiry(end) else
                       f"until {until} (in {_left(r['left'])})" if r["status"] == "active" else f"ended or ends {until}"))
            if r["hints"]:
                out.append("  " + ui.c("renew soon: " + "; ".join(r["hints"]), "warn", bold=True))
                out.append(f"  renew: {r['renew']}")
                out.append("  (the old grant keeps working until it runs out or you revoke it)")
            out.append("")
    if hidden:
        out.append(f"{hidden} more not open (expired, revoked, used up or stale): synthe-task grants --all")
    return "\n".join(out).rstrip()


def revoke(client, home: Path, grant_id: str, key=None, passphrase: bool = False, out=print) -> dict:
    import synthe_task as stk
    s = stk.setup_of(home)
    known = {t["template_id"]: t for t in client.call("lane_templates").get("templates") or []}
    if grant_id not in known:
        raise SystemExit(f"no grant {grant_id!r}; synthe-task grants --all lists them"
                         + (f" (closest: {', '.join(sorted(known)[:5])})" if known else ""))
    key = key or unlock_key(home, s["sender"], f"revoke lane grant {grant_id}", passphrase)
    try:
        signed = lanes.sign({"template_id": grant_id}, key, revoke=True)
    except touchid.TouchIDError as e:
        raise SystemExit(f"not signed: {e}")
    try:
        result = client.call("revoke_lane_template", revocation=signed)
    except scl.BrokerError as e:
        raise SystemExit(f"the broker refused the revocation: {e.code}: {e.message}")
    out(f"Lane closed: {grant_id}. Pushes in it ask you again.")
    return result


# ---- setup: "how hands-off?" -----------------------------------------------------------------

QUESTION = """How hands-off?
  [1] Ask me before every push
  [2] Agents push without asking; Synthe only interrupts for what it blocks or flags as high-risk (recommended)"""


def _connect(broker: str, tries: int, sleep):
    """The broker was started moments ago by the admin step: give it a few seconds to listen."""
    for n in range(tries):
        try:
            c = scl.BrokerClient(broker)
            c.call("hello")
            return c
        except scl.BrokerError as e:
            if e.code != "broker_unreachable" or n == tries - 1:
                raise
            sleep(1)


def offer_lane(home: Path, *, interactive: bool | None = None, ask=input, out=print, client=None, key=None,
               confirm=None, tries: int = 10, sleep=time.sleep) -> str:
    """Ask once at the end of setup. Returns "lane" if a default grant was signed, else "ask" (today's
    behaviour, and the only outcome without a person at a terminal: nothing is ever granted silently).
    At a terminal, Return alone picks [2], the recommended choice; it still shows the terms and asks before
    anything is signed. Option 2 is the same code as `synthe-task grant` with the defaults from your setup:
    its branches and allowed paths, no use limit, no expiry (until you revoke it)."""
    if interactive is None:
        interactive = _terminal()
    later = "Open a lane any time: synthe-task grant"
    if not interactive:
        out(f"Every push will ask you (the default). {later}")
        return "ask"
    out("\n" + QUESTION)
    try:
        choice = ask("Choose 1 or 2 [2]: ").strip() or "2"
    except EOFError:
        choice = "1"
    if choice != "2":
        out(f"Every push will ask you. {later}")
        return "ask"
    import synthe_task as stk
    try:
        s = stk.setup_of(home)
        client = client or _connect(s["broker"], tries, sleep)
        made = 0
        for pattern in s["remote"].get("branches") or []:
            made += bool(issue(home, client=client, key=key, confirm=confirm, out=out, branch=pattern,
                               paths=list(s["policy"].get("allowed_paths") or []),
                               question="Sign it with your key? [Y/n] "))
    except (SystemExit, scl.BrokerError) as e:
        out(f"Couldn't open a lane: {e}\nEvery push will ask you. {later}")
        return "ask"
    return "lane" if made else "ask"


# ---- the synthe-task subcommands ---------------------------------------------------------------

def add_parsers(sub) -> None:
    g = sub.add_parser("grant", help="let routine pushes inside a lane go without asking you (signs a lane grant)")
    g.add_argument("--branch", help="branch pattern, e.g. 'agent/*' (default: your setup's branches)")
    g.add_argument("--paths", help="comma-separated globs the agent may change (default: your setup's allowed paths)")
    g.add_argument("--uses", type=int, help=f"cap the number of pushes, 1 to {UNLIMITED_USES} (default: no limit)")
    g.add_argument("--until", help="cap how long it stays open: 90m, 12h, 7d, 2w, or a date (default: no expiry; "
                                   "it stays open until you revoke it)")
    g.add_argument("--remote", default="origin")
    g.add_argument("--agent", help="the agent this applies to (default: the one in your setup)")
    g.add_argument("--delegate", help="a registered model approver that reviews each push instead of you")
    g.add_argument("--brief", help="your instructions to that reviewer (signed with the grant)")
    g.add_argument("--passphrase", action="store_true", help="sign with the passphrase key even if Touch ID is set up")
    g.add_argument("--home", default="~/.synthe")
    ls = sub.add_parser("grants", help="list open lanes: uses left, expiry, and which to renew")
    ls.add_argument("--all", action="store_true", help="include expired, revoked, used-up and stale grants")
    ls.add_argument("--home", default="~/.synthe")
    r = sub.add_parser("revoke-grant", help="close a lane now")
    r.add_argument("id")
    r.add_argument("--passphrase", action="store_true")
    r.add_argument("--home", default="~/.synthe")


def run(a) -> int:
    import synthe_task as stk
    home = Path(a.home).expanduser()
    s = stk.setup_of(home)  # a missing or broken setup fails here, before any prompt
    try:
        client = scl.BrokerClient(s["broker"])
        if a.cmd == "grants":
            print(render_grants(list_grants(client), a.all))
            return 0
        if not _terminal():
            print(f"synthe-task {a.cmd} is interactive: run it in your own terminal (it signs with your key).",
                  file=sys.stderr)
            return 2
        if a.cmd == "revoke-grant":
            revoke(client, home, a.id, passphrase=a.passphrase)
            return 0
        patterns = [a.branch] if a.branch else list(s["remote"].get("branches") or [])
        if len(patterns) != 1:
            raise SystemExit("--branch: say which branch pattern, e.g. 'agent/*' (your setup has "
                             f"{len(patterns)}: {', '.join(patterns) or 'none'})")
        issue(home, client=client, passphrase=a.passphrase, branch=patterns[0],
              paths=_csv(a.paths) if a.paths else list(s["policy"].get("allowed_paths") or []), uses=a.uses,
              until=a.until, remote=a.remote, receiver=a.agent, delegate=a.delegate, brief=a.brief)
    except scl.BrokerError as e:
        raise SystemExit(f"synthe-task: {e.code}: {e.message}")
    return 0
