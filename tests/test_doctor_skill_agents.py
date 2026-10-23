"""synthe-init doctor's skill check with several OpenClaw agents.

Recent OpenClaw refuses `skills info` without --agent when more than one agent is configured. The doctor
read that refusal as "the synthe skill is missing" (seen live on 2026-10-22 after an upgrade). It now asks
each configured agent and reports a missing skill only when one really lacks it."""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import synthe_init as si  # noqa: E402

MULTI = {"ok": False, "error": {"type": "cli_error",
                                "message": "Multiple agents are configured, but the skills command has no "
                                           "explicit owner. Pass --agent <id>."}}


class FakeOpenClaw:
    def __init__(self, tmp_path, agents, per_agent, top=MULTI):
        self.cfg = tmp_path / "openclaw.json"
        self.cfg.write_text(json.dumps({"agents": {"entries": {a: {} for a in agents}}}))
        self.per_agent, self.top, self.calls = per_agent, top, []

    def config_path(self):
        return self.cfg

    def run(self, *args, interactive=False):
        self.calls.append(args)
        if args[:3] == ("skills", "info", "synthe"):
            if "--agent" in args:
                agent = args[args.index("--agent") + 1]
                out = {"skill": {"name": "synthe", "eligible": self.per_agent.get(agent, False)}}
            else:
                out = self.top
            return subprocess.CompletedProcess(args, 0, json.dumps(out), "")
        return subprocess.CompletedProcess(args, 1, "", "")


def test_single_agent_answer_still_passes(tmp_path):
    oc = FakeOpenClaw(tmp_path, ["main"], {}, top={"skill": {"eligible": True}})
    assert si._skill_check(oc)[0] == "PASS"


def test_multiple_agents_are_each_asked_and_pass_when_all_have_the_skill(tmp_path):
    oc = FakeOpenClaw(tmp_path, ["main", "builder"], {"main": True, "builder": True})
    status, _, detail = si._skill_check(oc)
    assert status == "PASS" and "builder, main" in detail
    assert ("skills", "info", "synthe", "--agent", "builder", "--json") in oc.calls


def test_multiple_agents_name_the_one_missing_the_skill(tmp_path):
    oc = FakeOpenClaw(tmp_path, ["main", "builder"], {"main": True, "builder": False})
    status, _, detail = si._skill_check(oc)
    assert status == "WARN" and detail.endswith("agent(s): builder")


def test_multiple_agents_with_no_readable_config_warn_with_the_command_to_run(tmp_path):
    oc = FakeOpenClaw(tmp_path, [], {})
    oc.cfg.write_text("not json")
    status, _, detail = si._skill_check(oc)
    assert status == "WARN" and "--agent <id>" in detail


def test_other_failures_are_still_a_missing_skill(tmp_path):
    oc = FakeOpenClaw(tmp_path, ["main"], {}, top={"ok": False, "error": {"message": "unknown skill synthe"}})
    assert si._skill_check(oc) == ("WARN", "synthe skill", "the synthe skill is missing or ineligible")


def _wire(tmp_path, monkeypatch, oc):
    integ = tmp_path / "integ"
    (integ / "skill" / "synthe").mkdir(parents=True)
    monkeypatch.setattr(si, "integration_dir", lambda: integ)
    steps = si.wire_openclaw(oc, tmp_path / "home", True)
    return [a for a in oc.calls if a[:2] == ("skills", "install")], steps


def test_setup_installs_the_skill_for_each_configured_agent(tmp_path, monkeypatch):
    oc = FakeOpenClaw(tmp_path, ["coordinator", "writer"], {})
    installs, steps = _wire(tmp_path, monkeypatch, oc)
    assert [a[a.index("--agent") + 1] for a in installs] == ["coordinator", "writer"]
    assert {name for name, _, _ in steps} >= {"skill (coordinator)", "skill (writer)"}


def test_setup_without_listed_agents_installs_the_skill_once(tmp_path, monkeypatch):
    oc = FakeOpenClaw(tmp_path, [], {})
    oc.cfg.unlink()
    installs, _ = _wire(tmp_path, monkeypatch, oc)
    assert len(installs) == 1 and "--agent" not in installs[0]
