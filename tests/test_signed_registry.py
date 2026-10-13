"""Signed registry: sign/verify/tamper/rotation, loader fail-closed, CLI gates.

Item 1 of the Synthe build queue. The registry file carries an Ed25519
operator signature over its canonical body plus a verifiable rotation chain;
the checker rejects anything whose signature does not verify with
registry_signature_invalid.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import synthe_crypto as sc
import handoff_check as hc


@pytest.fixture()
def op_key():
    secret = sc.generate_secret()
    return {"secret": secret, "kid": "op-1", "pub": sc.public_key(secret)}


@pytest.fixture()
def op_key2():
    secret = sc.generate_secret()
    return {"secret": secret, "kid": "op-2", "pub": sc.public_key(secret)}


def body():
    return {"agents": {"cora": {"role": "cto", "keys": []},
                       "caddy": {"role": "rules-integration", "keys": []}}}


def write(path: Path, obj: dict) -> Path:
    path.write_text(json.dumps(obj, indent=2))
    return path


# ---------------------------------------------------------------- signing

def test_genesis_sign_verifies(op_key):
    signed = sc.sign_registry(body(), op_key["secret"], op_key["kid"])
    ok, info = sc.verify_registry_signature(signed)
    assert ok, info
    assert info == {"kid": "op-1", "chain_length": 1}
    genesis = signed["signature"]["chain"][0]
    assert genesis["seq"] == 0
    assert genesis["public_key"] == sc.b64u(op_key["pub"])
    # the genesis attestation is self-issued: it verifies under its own key
    assert sc.verify_bytes(op_key["pub"], sc.rotation_signing_input(genesis),
                           sc.unb64u(genesis["sig"]))


def test_signing_covers_canonical_body(op_key):
    # key order / whitespace must not matter: the signature is over canonical JSON
    a = sc.sign_registry({"agents": {"b": 1, "a": 2}}, op_key["secret"], op_key["kid"])
    reordered = {"agents": {"a": 2, "b": 1}, "signature": a["signature"]}
    ok, _ = sc.verify_registry_signature(reordered)
    assert ok


def test_one_byte_tamper_fails_closed(op_key):
    signed = sc.sign_registry(body(), op_key["secret"], op_key["kid"])
    tampered = json.loads(json.dumps(signed))
    tampered["agents"]["caddy"]["role"] = "rules-integratioo"  # one byte
    ok, reason = sc.verify_registry_signature(tampered)
    assert not ok
    assert "body signature" in reason


def test_added_agent_fails_closed(op_key):
    signed = sc.sign_registry(body(), op_key["secret"], op_key["kid"])
    tampered = json.loads(json.dumps(signed))
    tampered["agents"]["mallory"] = {"role": "attacker", "keys": []}
    ok, _ = sc.verify_registry_signature(tampered)
    assert not ok


def test_tampered_body_sig_fails_closed(op_key):
    signed = sc.sign_registry(body(), op_key["secret"], op_key["kid"])
    tampered = json.loads(json.dumps(signed))
    sig = bytearray(sc.unb64u(tampered["signature"]["sig"]))
    sig[0] ^= 1
    tampered["signature"]["sig"] = sc.b64u(bytes(sig))
    ok, reason = sc.verify_registry_signature(tampered)
    assert not ok
    assert "body signature" in reason


def test_missing_signature_block_rejected():
    ok, reason = sc.verify_registry_signature(body())
    assert not ok
    assert "no 'signature' block" in reason


def test_wrong_alg_rejected(op_key):
    signed = sc.sign_registry(body(), op_key["secret"], op_key["kid"])
    signed["signature"]["alg"] = "ES256"
    ok, reason = sc.verify_registry_signature(signed)
    assert not ok
    assert "Ed25519" in reason


# ---------------------------------------------------------------- rotation

def test_rotation_produces_verifiable_chain(op_key, op_key2):
    signed = sc.sign_registry(body(), op_key["secret"], op_key["kid"])
    rotated = sc.rotate_registry_key(signed, op_key["secret"], op_key2["secret"], op_key2["kid"])
    ok, info = sc.verify_registry_signature(rotated)
    assert ok, info
    assert info == {"kid": "op-2", "chain_length": 2}
    chain = rotated["signature"]["chain"]
    assert chain[1]["supersedes"] == "op-1"
    assert chain[1]["public_key"] == sc.b64u(op_key2["pub"])
    # the attestation is signed by the OLD key, over the domain-separated input
    assert sc.verify_bytes(op_key["pub"], sc.rotation_signing_input(chain[1]),
                           sc.unb64u(chain[1]["sig"]))
    # and the body is now signed by the NEW key
    assert sc.verify_bytes(op_key2["pub"], sc.registry_signing_input(rotated),
                           sc.unb64u(rotated["signature"]["sig"]))


def test_rotation_chain_survives_second_rotation(op_key, op_key2):
    third = {"secret": sc.generate_secret(), "kid": "op-3"}
    r1 = sc.rotate_registry_key(sc.sign_registry(body(), op_key["secret"], op_key["kid"]),
                                op_key["secret"], op_key2["secret"], op_key2["kid"])
    r2 = sc.rotate_registry_key(r1, op_key2["secret"], third["secret"], third["kid"])
    ok, info = sc.verify_registry_signature(r2)
    assert ok
    assert info == {"kid": "op-3", "chain_length": 3}
    assert [e["seq"] for e in r2["signature"]["chain"]] == [0, 1, 2]


def test_rotation_with_wrong_old_key_fails(op_key, op_key2):
    signed = sc.sign_registry(body(), op_key["secret"], op_key["kid"])
    stranger = sc.generate_secret()
    with pytest.raises(ValueError, match="old key does not match"):
        sc.rotate_registry_key(signed, stranger, op_key2["secret"], op_key2["kid"])


def test_rotation_on_tampered_registry_fails(op_key, op_key2):
    signed = sc.sign_registry(body(), op_key["secret"], op_key["kid"])
    tampered = json.loads(json.dumps(signed))
    tampered["agents"]["mallory"] = {"role": "attacker"}
    with pytest.raises(ValueError, match="current registry signature invalid"):
        sc.rotate_registry_key(tampered, op_key["secret"], op_key2["secret"], op_key2["kid"])


def test_tampered_chain_fails_closed(op_key, op_key2):
    r1 = sc.rotate_registry_key(sc.sign_registry(body(), op_key["secret"], op_key["kid"]),
                                op_key["secret"], op_key2["secret"], op_key2["kid"])
    tampered = json.loads(json.dumps(r1))
    # attacker swaps the new key for their own in the chain entry
    evil = sc.generate_secret()
    tampered["signature"]["chain"][1]["public_key"] = sc.b64u(sc.public_key(evil))
    ok, reason = sc.verify_registry_signature(tampered)
    assert not ok
    assert "rotation attestation" in reason


def test_old_key_cannot_sign_after_rotation(op_key, op_key2):
    """After rotation, a body signed by the retired key must not verify."""
    r1 = sc.rotate_registry_key(sc.sign_registry(body(), op_key["secret"], op_key["kid"]),
                                op_key["secret"], op_key2["secret"], op_key2["kid"])
    forged = json.loads(json.dumps(r1))
    forged["signature"]["kid"] = "op-1"
    forged["signature"]["sig"] = sc.b64u(sc.sign_bytes(op_key["secret"],
                                                      sc.registry_signing_input(forged)))
    ok, reason = sc.verify_registry_signature(forged)
    assert not ok  # kid op-1 is not the chain's current key


def test_resign_preserves_chain_after_body_edit(op_key, op_key2):
    r1 = sc.rotate_registry_key(sc.sign_registry(body(), op_key["secret"], op_key["kid"]),
                                op_key["secret"], op_key2["secret"], op_key2["kid"])
    edited = json.loads(json.dumps(r1))
    edited["agents"]["caddy"]["role"] = "rules-integration-v2"
    # the old body signature is stale after a legitimate edit: plain re-sign refuses
    with pytest.raises(ValueError, match="current registry signature invalid"):
        sc.resign_registry(edited, op_key2["secret"])
    # --force re-signs after a legitimate edit; the chain is still verified
    resigned = sc.resign_registry(edited, op_key2["secret"], force=True)
    ok, info = sc.verify_registry_signature(resigned)
    assert ok
    assert info["chain_length"] == 2
    assert resigned["agents"]["caddy"]["role"] == "rules-integration-v2"


def test_resign_force_still_rejects_broken_chain(op_key, op_key2):
    r1 = sc.rotate_registry_key(sc.sign_registry(body(), op_key["secret"], op_key["kid"]),
                                op_key["secret"], op_key2["secret"], op_key2["kid"])
    edited = json.loads(json.dumps(r1))
    edited["agents"]["caddy"]["role"] = "rules-integration-v2"
    edited["signature"]["chain"][1]["sig"] = sc.b64u(b"\x00" * 64)  # break the chain, not just the body
    with pytest.raises(ValueError, match="rotation chain invalid"):
        sc.resign_registry(edited, op_key2["secret"], force=True)


def test_resign_with_wrong_key_fails(op_key, op_key2):
    signed = sc.sign_registry(body(), op_key["secret"], op_key["kid"])
    with pytest.raises(ValueError, match="not the registry's current operator key"):
        sc.resign_registry(signed, op_key2["secret"])


# ---------------------------------------------------------------- loader

def _op_pin(op_key) -> str:
    return sc.b64u(op_key["pub"])


def test_loader_accepts_signed_registry(tmp_path, op_key):
    p = write(tmp_path / "registry.json", sc.sign_registry(body(), op_key["secret"], op_key["kid"]))
    reg, err = hc.load_registry(str(p), genesis_key=_op_pin(op_key))
    assert err is None
    assert reg is not None
    assert "signature" not in reg  # signature block is stripped before use
    assert reg["agents"]["cora"]["role"] == "cto"


def test_loader_rejects_tampered_registry(tmp_path, op_key):
    signed = sc.sign_registry(body(), op_key["secret"], op_key["kid"])
    signed["agents"]["mallory"] = {"role": "attacker"}
    p = write(tmp_path / "registry.json", signed)
    reg, err = hc.load_registry(str(p), genesis_key=_op_pin(op_key))
    assert reg is None
    assert err["decision"] == "REJECT"
    assert err["reasons"][0]["code"] == "registry_signature_invalid"


def test_loader_unsigned_default_and_strict(tmp_path, monkeypatch):
    """No pin: an unsigned registry loads (today's behavior); a caller that
    demands a signed registry (allow_unsigned=False) is refused and told to pin."""
    monkeypatch.setattr(hc, "resolve_genesis_pin", lambda explicit=None: None)
    p = write(tmp_path / "registry.json", body())
    reg, err = hc.load_registry(str(p))
    assert err is None and reg["agents"]["cora"]["role"] == "cto"
    reg, err = hc.load_registry(str(p), allow_unsigned=False)
    assert reg is None
    assert err["reasons"][0]["code"] == "registry_signature_invalid"
    assert "no genesis key is pinned" in err["reasons"][0]["message"]


def test_loader_rejects_unsigned_when_pinned(tmp_path, op_key):
    """With a pin, an unsigned registry is a downgrade: refused even when the
    caller would otherwise accept unsigned (the daemons pass allow_unsigned=True)."""
    p = write(tmp_path / "registry.json", body())
    reg, err = hc.load_registry(str(p), allow_unsigned=True, genesis_key=_op_pin(op_key))
    assert reg is None
    assert err["reasons"][0]["code"] == "registry_signature_invalid"
    assert "must be signed" in err["reasons"][0]["message"]


def test_loader_accepts_unsigned_with_explicit_opt_in(tmp_path):
    p = write(tmp_path / "registry.json", body())
    reg, err = hc.load_registry(str(p), allow_unsigned=True)
    assert err is None
    assert reg["agents"]["cora"]["role"] == "cto"


def test_loader_rejects_malformed_signature_block(tmp_path, op_key):
    bad = {**body(), "signature": {"alg": "Ed25519"}}  # no chain
    p = write(tmp_path / "registry.json", bad)
    reg, err = hc.load_registry(str(p), genesis_key=_op_pin(op_key))
    assert reg is None
    assert err["reasons"][0]["code"] == "registry_signature_invalid"


# ---------------------------------------------------------------- CLI

def _run(*args):
    return subprocess.run([sys.executable, *args], capture_output=True, text=True, cwd=ROOT)


def _signed_example_registry(tmp_path, op_key):
    reg = json.loads((ROOT / "examples" / "registry.json").read_text())
    return write(tmp_path / "registry.json",
                 sc.sign_registry(reg, op_key["secret"], op_key["kid"]))


def test_cli_accepts_signed_registry(tmp_path, op_key):
    reg = _signed_example_registry(tmp_path, op_key)
    r = _run("src/handoff_check.py", "examples/valid.json",
             "--registry", str(reg), "--workspace", ".",
             "--registry-genesis-key", _op_pin(op_key))
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads(r.stdout)["decision"] == "ACCEPT"


def test_cli_rejects_tampered_registry(tmp_path, op_key):
    reg = _signed_example_registry(tmp_path, op_key)
    tampered = json.loads(reg.read_text())
    tampered["agents"]["mallory"] = {"role": "attacker"}
    reg.write_text(json.dumps(tampered))
    r = _run("src/handoff_check.py", "examples/valid.json",
             "--registry", str(reg), "--workspace", ".",
             "--registry-genesis-key", _op_pin(op_key))
    assert r.returncode == 2, r.stdout + r.stderr
    out = json.loads(r.stdout)
    assert out["decision"] == "REJECT"
    assert out["reasons"][0]["code"] == "registry_signature_invalid"


def test_cli_unsigned_loads_with_warning_by_default(tmp_path, monkeypatch):
    monkeypatch.delenv("SYNTHE_REGISTRY_GENESIS_KEY", raising=False)
    reg = tmp_path / "registry.json"
    unsigned = json.loads((ROOT / "examples" / "registry.json").read_text())
    unsigned.pop("signature", None)
    reg.write_text(json.dumps(unsigned))
    r = _run_env("src/handoff_check.py", "examples/valid.json",
                 "--registry", str(reg), "--workspace", ".", env={})
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads(r.stdout)["decision"] == "ACCEPT"
    assert "NOT verified" in r.stderr


def test_cli_require_signed_registry_refuses_without_pin(tmp_path, monkeypatch):
    monkeypatch.delenv("SYNTHE_REGISTRY_GENESIS_KEY", raising=False)
    r = _run_env("src/handoff_check.py", "examples/valid.json",
                 "--registry", "examples/registry.json", "--workspace", ".",
                 "--require-signed-registry", env={})
    assert r.returncode == 2, r.stdout + r.stderr
    out = json.loads(r.stdout)
    assert out["reasons"][0]["code"] == "registry_signature_invalid"


def _write_op_keyfile(path: Path, kid: str, secret: bytes = None) -> bytes:
    secret = secret or sc.generate_secret()
    path.write_text(json.dumps({"v": "synthe-key/v2", "agent": "operator", "kid": kid,
                                "alg": "Ed25519", "public_key": sc.b64u(sc.public_key(secret)),
                                "private_key": sc.b64u(secret)}))
    return secret


def test_sign_registry_cli_genesis_and_rotation(tmp_path):
    key1 = tmp_path / "op1.key.json"
    s1 = _write_op_keyfile(key1, "op-1")
    key2 = tmp_path / "op2.key.json"
    s2 = _write_op_keyfile(key2, "op-2")
    reg = tmp_path / "registry.json"
    reg.write_text(json.dumps(body()))

    r = _run("src/synthe_sign.py", "sign-registry", "--registry", str(reg),
             "--key", str(key1), "--kid", "op-1")
    assert r.returncode == 0, r.stderr
    signed = json.loads(reg.read_text())
    ok, info = sc.verify_registry_signature(signed)
    assert ok and info["chain_length"] == 1

    r = _run("src/synthe_sign.py", "rotate-registry-key", "--registry", str(reg),
             "--old-key", str(key1), "--new-key", str(key2), "--new-kid", "op-2")
    assert r.returncode == 0, r.stderr
    rotated = json.loads(reg.read_text())
    ok, info = sc.verify_registry_signature(rotated)
    assert ok and info == {"kid": "op-2", "chain_length": 2}
    assert rotated["signature"]["chain"][1]["public_key"] == sc.b64u(sc.public_key(s2))

    # loader accepts the rotated registry (genesis pin = the original operator key)
    loaded, err = hc.load_registry(str(reg), genesis_key=sc.b64u(sc.public_key(s1)))
    assert err is None and loaded["agents"]["cora"]["role"] == "cto"
    _ = s1  # old secret stays valid only for chain verification, not body signing


def test_sign_registry_cli_refuses_tampered(tmp_path):
    key1 = tmp_path / "op1.key.json"
    _write_op_keyfile(key1, "op-1")
    reg = tmp_path / "registry.json"
    reg.write_text(json.dumps(body()))
    assert _run("src/synthe_sign.py", "sign-registry", "--registry", str(reg),
                "--key", str(key1)).returncode == 0
    tampered = json.loads(reg.read_text())
    tampered["agents"]["mallory"] = {"role": "attacker"}
    reg.write_text(json.dumps(tampered))
    # re-signing a tampered registry must fail closed, not launder it
    r = _run("src/synthe_sign.py", "sign-registry", "--registry", str(reg),
             "--key", str(key1))
    assert r.returncode == 2
    assert "invalid" in r.stderr
    assert "--force" in r.stderr
    # --force after a legitimate operator edit re-signs and preserves the chain
    reg.write_text(json.dumps(body()))
    assert _run("src/synthe_sign.py", "sign-registry", "--registry", str(reg),
                "--key", str(key1)).returncode == 0
    edited = json.loads(reg.read_text())
    edited["agents"]["caddy"]["role"] = "rules-integration-edited"
    reg.write_text(json.dumps(edited))
    r = _run("src/synthe_sign.py", "sign-registry", "--registry", str(reg),
             "--key", str(key1), "--force")
    assert r.returncode == 0, r.stderr
    ok, info = sc.verify_registry_signature(json.loads(reg.read_text()))
    assert ok and info["chain_length"] == 1


def test_rotate_registry_cli_wrong_old_key(tmp_path):
    key1 = tmp_path / "op1.key.json"
    _write_op_keyfile(key1, "op-1")
    stranger = tmp_path / "stranger.key.json"
    _write_op_keyfile(stranger, "evil")
    key2 = tmp_path / "op2.key.json"
    _write_op_keyfile(key2, "op-2")
    reg = tmp_path / "registry.json"
    reg.write_text(json.dumps(body()))
    assert _run("src/synthe_sign.py", "sign-registry", "--registry", str(reg),
                "--key", str(key1)).returncode == 0
    r = _run("src/synthe_sign.py", "rotate-registry-key", "--registry", str(reg),
             "--old-key", str(stranger), "--new-key", str(key2), "--new-kid", "op-2")
    assert r.returncode == 2
    assert "old key does not match" in r.stderr


# ---------------------------------------------------------------- v2: genesis pin

def test_loader_rejects_wrong_genesis_pin(tmp_path, op_key, op_key2):
    """A self-consistent registry signed by someone else's key must fail closed
    when the pin names a different genesis key (the v1 trust-anchor hole)."""
    p = write(tmp_path / "registry.json", sc.sign_registry(body(), op_key["secret"], op_key["kid"]))
    reg, err = hc.load_registry(str(p), genesis_key=_op_pin(op_key2))
    assert reg is None
    assert err["decision"] == "REJECT"
    assert err["reasons"][0]["code"] == "registry_signature_invalid"
    assert "genesis" in err["reasons"][0]["message"]


def test_loader_treats_signed_as_unsigned_without_pin(tmp_path, op_key, monkeypatch):
    """No pin configured: a self-issued signature proves nothing, so it is not
    verified and the registry loads as unsigned; strict callers are refused."""
    monkeypatch.setattr(hc, "resolve_genesis_pin", lambda explicit=None: None)
    signed = sc.sign_registry(body(), op_key["secret"], op_key["kid"])
    signed["agents"]["mallory"] = {"role": "attacker"}  # unverifiable either way
    p = write(tmp_path / "registry.json", signed)
    reg, err = hc.load_registry(str(p))
    assert err is None and "signature" not in reg
    reg, err = hc.load_registry(str(p), allow_unsigned=False)
    assert reg is None and err["reasons"][0]["code"] == "registry_signature_invalid"


def test_genesis_pin_fingerprint_form_accepted(tmp_path, op_key):
    import hashlib
    fp = hashlib.sha256(op_key["pub"]).hexdigest()
    p = write(tmp_path / "registry.json", sc.sign_registry(body(), op_key["secret"], op_key["kid"]))
    reg, err = hc.load_registry(str(p), genesis_key=fp)
    assert err is None, err
    assert reg["agents"]["cora"]["role"] == "cto"


def test_genesis_pin_bad_value_rejected(tmp_path, op_key):
    p = write(tmp_path / "registry.json", sc.sign_registry(body(), op_key["secret"], op_key["kid"]))
    reg, err = hc.load_registry(str(p), genesis_key="not-a-key")
    assert reg is None
    assert err["reasons"][0]["code"] == "registry_signature_invalid"
    assert "bad genesis pin" in err["reasons"][0]["message"]


def test_missing_alg_rejected(op_key):
    signed = sc.sign_registry(body(), op_key["secret"], op_key["kid"])
    del signed["signature"]["alg"]
    ok, reason = sc.verify_registry_signature(signed, genesis_pin=_op_pin(op_key))
    assert not ok
    assert "alg" in reason


def test_duplicate_kid_in_chain_rejected(op_key, op_key2):
    r1 = sc.rotate_registry_key(sc.sign_registry(body(), op_key["secret"], op_key["kid"]),
                                op_key["secret"], op_key2["secret"], op_key2["kid"])
    dup = json.loads(json.dumps(r1))
    dup["signature"]["chain"][1]["kid"] = "op-1"  # kid reuse: chain is self-consistent but forked
    ok, reason = sc.verify_registry_signature(dup, genesis_pin=_op_pin(op_key))
    assert not ok
    assert "already appears" in reason


def _run_env(*args, env):
    merged = dict(os.environ)
    merged.update(env)
    return subprocess.run([sys.executable, *args], capture_output=True, text=True,
                          cwd=ROOT, env=merged)


def test_cli_genesis_pin_via_env(tmp_path, op_key, monkeypatch):
    """SYNTHE_REGISTRY_GENESIS_KEY is honored when no flag is given."""
    monkeypatch.delenv("SYNTHE_REGISTRY_GENESIS_KEY", raising=False)
    reg = _signed_example_registry(tmp_path, op_key)
    r = _run_env("src/handoff_check.py", "examples/valid.json",
                 "--registry", str(reg), "--workspace", ".",
                 env={"SYNTHE_REGISTRY_GENESIS_KEY": _op_pin(op_key)})
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads(r.stdout)["decision"] == "ACCEPT"


def test_cli_genesis_pin_precedence_flag_over_env(tmp_path, op_key, op_key2, monkeypatch):
    """Flag beats env: env pins the wrong key, the flag pins the right one."""
    monkeypatch.delenv("SYNTHE_REGISTRY_GENESIS_KEY", raising=False)
    reg = _signed_example_registry(tmp_path, op_key)
    r = _run_env("src/handoff_check.py", "examples/valid.json",
                 "--registry", str(reg), "--workspace", ".",
                 "--registry-genesis-key", _op_pin(op_key),
                 env={"SYNTHE_REGISTRY_GENESIS_KEY": _op_pin(op_key2)})
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads(r.stdout)["decision"] == "ACCEPT"


def test_no_pin_file_ships_with_the_checker():
    """Nothing in the repo pins a key by default: a shipped pin to a throwaway
    key would make every default install trust whoever holds that key."""
    assert not (ROOT / "src" / hc.GENESIS_PIN_FILENAME).exists()
    assert not (ROOT / "github-action" / "checker" / hc.GENESIS_PIN_FILENAME).exists()


def test_operator_pin_file_next_to_checker_is_honored(tmp_path, op_key, op_key2, monkeypatch):
    """An operator-provisioned registry-genesis.key next to the checker pins the
    key; env beats the file, the flag beats both."""
    monkeypatch.delenv("SYNTHE_REGISTRY_GENESIS_KEY", raising=False)
    monkeypatch.setattr(hc, "__file__", str(tmp_path / "handoff_check.py"))
    (tmp_path / hc.GENESIS_PIN_FILENAME).write_text("# operator pin\n" + _op_pin(op_key2) + "\n")
    p = write(tmp_path / "registry.json", sc.sign_registry(body(), op_key["secret"], op_key["kid"]))
    reg, err = hc.load_registry(str(p))
    assert reg is None and "genesis" in err["reasons"][0]["message"]  # file pins op_key2
    monkeypatch.setenv("SYNTHE_REGISTRY_GENESIS_KEY", _op_pin(op_key))
    reg, err = hc.load_registry(str(p))
    assert err is None
    reg, err = hc.load_registry(str(p), genesis_key=_op_pin(op_key2))
    assert reg is None


def test_cli_wrong_pin_rejects(tmp_path, op_key, op_key2):
    reg = _signed_example_registry(tmp_path, op_key)
    r = _run("src/handoff_check.py", "examples/valid.json",
             "--registry", str(reg), "--workspace", ".",
             "--registry-genesis-key", _op_pin(op_key2))
    assert r.returncode == 2, r.stdout + r.stderr
    out = json.loads(r.stdout)
    assert out["decision"] == "REJECT"
    assert out["reasons"][0]["code"] == "registry_signature_invalid"
    assert "genesis" in out["reasons"][0]["message"]


def test_cli_quickstart_with_and_without_example_pin(monkeypatch):
    """The quickstart works with no pin (unverified, warns) and verifies when the
    example key from examples/registry-genesis.pub is pinned explicitly."""
    monkeypatch.delenv("SYNTHE_REGISTRY_GENESIS_KEY", raising=False)
    r = _run_env("src/handoff_check.py", "examples/valid.json",
                 "--registry", "examples/registry.json", "--workspace", ".", env={})
    assert r.returncode == 0, r.stdout + r.stderr
    assert "NOT verified" in r.stderr
    pub = [l for l in (ROOT / "examples" / "registry-genesis.pub").read_text().splitlines()
           if l.strip() and not l.startswith("#")][0]
    r = _run_env("src/handoff_check.py", "examples/valid.json",
                 "--registry", "examples/registry.json", "--workspace", ".",
                 "--registry-genesis-key", pub, env={})
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads(r.stdout)["decision"] == "ACCEPT"
    assert "NOT verified" not in r.stderr