"""Startup must notice a dead broker and retain kernel uid verification."""
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
MUTATIONS = [
    ("src/synthe_mcp.py", '                server.client.call("hello")',
     '                pass  # mutation: skip startup hello', "test_dead_broker_exits_with_one_clear_stderr_line"),
    ("src/synthe_client.py", '                self._verify_broker_uid()  # before anything is sent',
     '                pass  # mutation: accept the wrong uid', "test_discovery_preserves_uid_pin"),
]


@pytest.mark.parametrize("rel,guard,mutant,test", MUTATIONS)
def test_startup_mutation_is_caught(tmp_path, rel, guard, mutant, test):
    shutil.copytree(ROOT / "src", tmp_path / "src", ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"))
    (tmp_path / "tests").mkdir()
    for name in ("test_plugin_mcp_startup.py", "test_openclaw_flow.py"):
        shutil.copy2(ROOT / "tests" / name, tmp_path / "tests" / name)
    plugin = tmp_path / "integrations/claude-code"
    plugin.mkdir(parents=True)
    shutil.copy2(ROOT / "integrations/claude-code/.mcp.json", plugin / ".mcp.json")
    target = tmp_path / rel
    text = target.read_text()
    assert text.count(guard) == 1
    target.write_text(text.replace(guard, mutant))
    result = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                             f"tests/test_plugin_mcp_startup.py::{test}"], cwd=tmp_path,
                            capture_output=True, text=True, timeout=60,
                            env={**os.environ, "PYTHONPATH": str(tmp_path / "src")})
    assert result.returncode == 1, result.stdout + result.stderr
    assert "1 failed" in result.stdout, "must fail the assertion, not collection or setup"
