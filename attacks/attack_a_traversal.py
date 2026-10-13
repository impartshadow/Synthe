"""ATTACK A (bug A): path traversal past declared capability paths.

A declared path glob `src/**` must never authorize `src/../.ssh/id_rsa`.
On v1 this prints ALLOWED / True (the bug); on v2 both must be rejected.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import handoff_check as hc

decl = {"version": "1", "paths": ["src/**"], "env": [], "tools": [], "network": False}

r = hc.check_capability_use(decl, "path", "src/../.ssh/id_rsa")
print("check_capability_use(paths=['src/**'], 'src/../.ssh/id_rsa') ->",
      "ALLOWED" if r is None else f"DENIED ({r['code']})")

print("_glob_covers('src', 'src/../secrets') ->",
      hc._glob_covers("src", "src/../secrets"))

r2 = hc.check_capability_use(decl, "path", "src/main.py")
print("sanity: check_capability_use(paths=['src/**'], 'src/main.py') ->",
      "ALLOWED" if r2 is None else f"DENIED ({r2['code']})")
