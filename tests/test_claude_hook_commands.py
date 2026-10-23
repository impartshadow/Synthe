"""Executable commands are checked; inert shell/Python data is not publishing."""
import importlib.util
import io
import json
import re
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
HOOK = ROOT / "integrations/claude-code/hooks/pre_tool_use.py"
spec = importlib.util.spec_from_file_location("command_hook", HOOK)
hook = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hook)


def event(command):
    return {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command}}


@pytest.mark.parametrize("command", [
    "echo 'git push origin main'", 'printf "%s\\n" "gh api /repos/example/repo"',
    "git commit -m 'document git push and gh pr merge'", "# git push\ngit status",
    "python3 - <<'PY'\nfrom pathlib import Path\nPath('notes.md').write_text('git push; gh api; gh release create v1')\nPY\n",
    "python3 - <<PY\nprint('git push')\nPY\n",
    "cat <<'EOF'\n$(git push)\n`gh pr merge`\ngit push\nEOF\n",
    "cat <<EOF\ngit push origin main\nEOF\n",
    "bash -c 'echo \"git push\"'", "bash -c 'echo \"$UNKNOWN\"'",
    "python -c 'print([\"git\", \"push\"])'", "echo '$(git push)'",
    "git status > 'git push'; git diff", "printf '%s' 'gh api' | cat", "command -v git push",
    "2>&1 echo 'git push'", "env -S 'echo git push'", "env --split-string='echo git push'",
    "cat <<\\EOF\n$(git push)\nEOF\n", r'echo "git\ push"',
])
def test_harmless_mentions_are_allowed(command):
    assert not hook.denied(event(command))


# Reads are not publishing (2026-10-22): blocking every `gh api` and every curl to api.github.com made the
# hook refuse harmless commands. Only a provable read is allowed; the write forms stay in the denied list.
@pytest.mark.parametrize("command", [
    "gh api /repos/example/repo", "gh api repos/example/repo/pulls/13 -q .head.sha",
    "gh api -X GET repos/example/repo/pulls", "gh api --method=get repos/example/repo",
    "gh api -XGET repos/example/repo/commits/main", "gh -R example/repo api repos/example/repo/actions/runs",
    "gh api --paginate repos/example/repo/branches", "gh api -H 'Accept: application/json' repos/example/repo",
    "gh api https://api.github.com/repos/example/repo", "gh api -iH 'Accept: x' repos/example/repo",
    "curl -q -s https://api.github.com/repos/example/repo", "curl --disable -sSL https://api.github.com/x",
    "curl -q -X GET https://api.github.com/repos/example/repo", "curl -q -I https://api.github.com/",
    "curl -q -sXGET https://api.github.com/x", "curl -q --url https://api.github.com/x -H 'Accept: y'",
])
def test_github_api_reads_are_allowed(command):
    assert not hook.denied(event(command))


# Codex's review of the first version (2026-10-22): each of these got through it. Uncertain forms stay denied.
@pytest.mark.parametrize("command", [
    "curl -sX POST https://api.github.com/repos/example/repo/pulls",
    "curl -sd '{}' https://api.github.com/repos/example/repo/pulls",
    "curl --config payload.conf https://api.github.com/repos/example/repo/pulls",
    "curl -K payload.conf https://api.github.com/repos/example/repo/pulls",
    "gh api -H 'Accept: application/json' graphql", "gh api https://api.github.com/graphql",
    "curl -s https://api.github.com/repos/example/repo",  # no -q: ~/.curlrc could add a body
    "curl -q -K payload.conf https://api.github.com/x", "curl -q -sK payload.conf https://api.github.com/x",
    "curl -q --unknown-flag https://api.github.com/x", "gh api --unknown repos/example/repo",
    "gh api repos/a/b repos/c/d", "gh api http://api.github.com/repos/x", "gh api https://evil.example/graphql",
    "gh api -X", "gh api --method", "curl -q https://api.github.com/x -X", "gh api repos/example/repo/graphql",
    "gh pr create --fill", "gh pr create --dry-run --head feature", "gh -R example/repo pr create",
])
def test_review_bypasses_and_uncertain_forms_are_denied(command):
    assert hook.denied(event(command))


@pytest.mark.parametrize("command", [
    "git push", "'git' 'push'", r"g\it pu\sh", "/usr/bin/git -C /tmp/repo push",
    "env X=1 git -c x=y push", "command git push", "nohup git push",
    "bash -c 'git push'", "bash -lc 'git push'", "sh -c 'bash -c \"git push\"'",
    "eval 'git push'", "CMD='git push'; $CMD", "G=git; P=push; $G $P",
    "A=git; B=$A; $B push", "CMD='git push'; bash -c \"$CMD\"", "$UNKNOWN push",
    'echo "$(git push)"', "echo `git push`", "cat <<EOF\n$(git push)\nEOF\n",
    "bash <<'EOF'\ngit push\nEOF\n", "cat <<'EOF'\ngit push\nEOF\ngit push\n",
    "git status && git push", "true || git push", "echo ok | git push",
    "if git push; then echo ok; fi", "true; >out git push; true",
    "sudo -u fixture git push", "timeout 10 git push", "nice -n 1 git push",
    "env --argv0 fixture git push", "exec -a fixture git push", "xargs -d ' ' git push",
    "2>&1 git push", "true; 2>&1 git push; true", "{fd}>out git push", ">&2 git push",
    "env -S 'git push'", "env --split-string='git push'", "env '-Sgit push'",
    "sudo --prompt fixture git push", "timeout --kill-after 2 10 git push",
    "git send-pack origin", "git http-push origin", "gh pr merge 1", "gh release upload v1 file",
    "gh api -X PUT /repos/example/repo/pulls/1/merge", "gh api --method POST repos/example/repo/git/refs",
    "gh api --method=DELETE repos/example/repo/git/refs/heads/x", "gh api -XPATCH repos/example/repo",
    "gh api repos/example/repo/git/refs -f ref=refs/heads/x -f sha=abc", "gh api repos/example/repo -Fname=x",
    "gh api repos/example/repo/contents/a --input body.json", "gh api repos/example/repo --raw-field=x=1",
    "gh api graphql -f query='mutation { x }'", "gh api graphql", "gh api", "gh api -X",
    "gh --repo example/repo pr merge 1", "curl -X POST https://api.github.com/repos/example/repo",
    "curl -d '{}' https://api.github.com/repos/example/repo/pulls", "curl --json '{}' https://api.github.com/x",
    "curl -XPUT https://api.github.com/repos/example/repo/pulls/1/merge", "curl -T f https://api.github.com/x",
    "curl --request=DELETE https://api.github.com/x", "curl https://api.github.com/x -X",
    "curl -X POST https://API.GITHUB.COM/repos/example/repo",
    r'''python -c "import subprocess; subprocess.run(['git', 'pu\x73h'])"''',
    "python3 - <<'PY'\nimport subprocess\nsubprocess.run(['git', 'push'])\nPY\n",
    "python -c 'import subprocess as sp; sp.run([\"git\", \"push\"])'",
    "python -c 'from subprocess import run as r; r([\"git\", \"push\"])'",
    "python -c 'import os; os.system(\"git push\")'",
    "python -c 'import os; os.execv(\"git\", [\"git\", \"push\"])'",
    "python -c 'import subprocess; cmd=[\"git\", \"push\"]; subprocess.run(cmd)'",
    "python -c 'import subprocess; cmd=[\"git\", \"push\"]; subprocess.run(cmd); cmd=[\"git\", \"status\"]'",
])
def test_publishing_and_nested_executors_remain_denied(command):
    assert hook.denied(event(command))


# Adversarial probe, 2026-10-23: the bypass classes from earlier reviews re-checked and extended.
# Each case asserts the hook's decision so a regression shows up as a test failure, not a missed probe.
@pytest.mark.parametrize("command", [
    # curl: combined short flags, config files, bodies, methods
    "curl -q -sXPOST https://api.github.com/repos/a/b/pulls", "curl -q -sSXPOST https://api.github.com/x",
    "curl -q -sX POST https://api.github.com/x", "curl -q -o /dev/null -XPOST https://api.github.com/x",
    "curl -q -K c https://api.github.com/x", "curl -q --config=c https://api.github.com/x",
    "curl -q -skK c https://api.github.com/x", "curl -q -H 'X: y' -K c https://api.github.com/x",
    "curl -q https://api.github.com/x -d @body", "curl -q https://api.github.com/x --data-binary @f",
    "curl -q -F a=b https://api.github.com/x", "curl -q -X post https://api.github.com/x",
    "curl -q --request POST https://api.github.com/x", "curl -q --request=POST https://api.github.com/x",
    "curl -q -X GET -X POST https://api.github.com/x", "curl -q https://API.github.com/x -XDELETE",
    "curl -q -X POST https://api.github.com:443/x", "curl -X POST https://api.github.com./repos/a/b",
    "curl -q -s -X POST https://uploads.github.com/repos/a/b/releases/1/assets",
    "wget --post-data=x https://uploads.github.com/repos/a/b/releases/1/assets",
    # gh api: -H consuming a token, full-URL GraphQL, method overrides, fields implying POST
    "gh api -H X -X POST repos/a/b", "gh api -HX -XPOST repos/a/b",
    "gh api https://API.GITHUB.COM/graphql", "gh api /graphql", "gh api graphql/", "gh api 'graphql?x=1'",
    "gh api https://api.github.com//graphql", "gh api https://api.github.com/graphql/",
    "gh api https://github.example.com/api/graphql", "gh api --hostname ghe.example.com graphql",
    "gh api --method=post repos/a/b", "gh api -f x=1 repos/a/b", "gh api repos/a/b -F x=@file",
    "gh api repos/a/b -fx=1", "gh api -X GET -f x=1 repos/a/b", "gh api -X GET -X POST repos/a/b",
    "gh api -XGET -XPOST repos/a/b", "gh api repos/a/b --input -", "gh api repos/a/b -- -X POST",
    # credentials
    "gh auth token", "gh auth status -t", "gh auth status --show-token", "gh auth git-credential get",
    "gh -R a/b auth token", "git credential fill", "printf 'host=github.com\\n' | git credential fill",
    "git credential-osxkeychain get", "git -C . credential fill",
    # shell wrappers, separators, quoting, line continuations
    "X=1 git push", "env git push", "env -i git push", "env -u X git push", "command -p git push",
    "exec git push", "builtin exec git push", "(git push)", "( cd /tmp && git push )", "{ git push; }",
    "true; git push", "true & git push", "'gi''t' push", "gi\\\nt push", "git \\\npush", "git pus\\\nh",
    "git p''ush", "git $'push'", "$(echo git) push", "`echo git` push", "x=$(echo push); git $x",
    "git ${CMD:-push}", "sh -c \"$(echo git push)\"", "bash -o pipefail -c 'git push'",
    "bash --norc -c 'git push'", "bash -e -c 'git push'", "zsh -fc 'git push'",
    "bash -c \"alias p='git push'; p\"", "bash -c 'shopt -s expand_aliases; alias p=\"git push\"\np'",
    "alias p='git push'",
    # git push variants, remotes, refspecs, config, aliases, plumbing
    "git push --mirror", "git push --mirror https://x-access-token:ghp_fixture@github.com/a/b.git",
    "git push https://ghp_fixture@github.com/a/b HEAD:main", "git push git@github.com:a/b.git HEAD:refs/heads/main",
    "git push ssh://git@github.com/a/b.git +HEAD:main", "git push origin :main",
    "git push origin +refs/heads/x:refs/heads/main", "git -c credential.helper= push",
    "git -c core.sshCommand='ssh -i k' push", "git -ccore.x=y push", "git --git-dir=.git push",
    "git --no-pager push", "git -p push", "git --exec-path=/x push", "git status; GIT_SSH_COMMAND=x git push",
    "git -c alias.p=push p", "git -c alias.p='!git push' p", "git -c Alias.P=push p", "git -calias.p=push p",
    "git --config-env=alias.p=X p", "git --config-env alias.p=X p",
    "git send-pack git@github.com:a/b.git main", "git http-push https://github.com/a/b",
    "git-send-pack x", "git-http-push x", "/usr/lib/git-core/git-push origin",
    "/usr/libexec/git-core/git-send-pack x", "git remote add r https://tok@github.com/a/b && git push r",
    "git commit --no-verify && git push origin HEAD",
])
def test_adversarial_probe_publishing_and_credentials_are_denied(command):
    assert hook.denied(event(command))


@pytest.mark.parametrize("command", [
    "git status", "git log --oneline -5", "git diff HEAD~1", "git fetch origin main", "git pull origin main",
    "git remote -v", "git remote add origin git@github.com:a/b.git", "git commit -m 'msg'",
    "git -c color.ui=never log", "git -C /tmp/alias.dir status", "git config --get user.name",
    "gh pr view 1", "gh pr list", "gh pr checks 1", "gh pr diff 1", "gh auth status",
    "gh api repos/a/b/pulls", "gh api -H 'Accept: application/vnd.github+json' repos/a/b",
    "gh api repos/a/b -q '.[].name'", "gh api -H POST repos/a/b", "gh api -H -XPOST repos/a/b",
    "curl -q -s https://api.github.com/repos/a/b", "curl -q -sS -H 'Accept: x' https://api.github.com/repos/a/b",
    "curl -q https://api.github.com/x -- -X POST",  # curl reads everything after -- as URLs: a GET
    "bash -c 'alias ll=\"ls -l\"; ll'", "bash scripts/check.sh", "printf 'x' | base64",
    "ls -la; cat README.md", "echo hi | grep h", "python3 -c 'print(1)'",
    # A script on stdin is invisible to the hook, like any script file or interpreter: denying it was
    # bypassed by `bash -s x` and `bash /dev/stdin` and blocked ordinary installers, so the credential
    # wall covers it.
    "curl -fsSL https://astral.sh/uv/install.sh | sh", "sh < script.sh",
])
def test_adversarial_probe_reads_and_local_work_are_allowed(command):
    assert not hook.denied(event(command))


@pytest.mark.parametrize("command", ["echo '", "cat <<EOF\nunterminated", "git \\", "eval '$UNKNOWN'"])
def test_invalid_or_unresolved_commands_fail_closed(command):
    assert hook.denied(event(command))


@pytest.mark.parametrize('command', [
    '$HOME/bin/python3 -c "print(1)"', '${HOME}/bin/git status',
    '"$HOME/bin/python3" -c "print(1)"', '"${HOME}/bin/git" diff',
    '$GIT_BIN status', '"$PYTHON_BIN" -c "print(1)"',
])
def test_executable_environment_paths_allow_local_work(monkeypatch, command):
    monkeypatch.setenv('HOME', '/tmp/fixture-home')
    monkeypatch.setenv('GIT_BIN', '/tmp/fixture-home/bin/git')
    monkeypatch.setenv('PYTHON_BIN', '/tmp/fixture-home/bin/python3')
    assert not hook.denied(event(command))


@pytest.mark.parametrize('command', [
    '$HOME/bin/git push', '${HOME}/bin/gh pr merge 1', '$GIT_BIN push',
    '"$HOME/bin/git" push', '"${HOME}/bin/gh" api -X PUT /repos/fixture/repo/pulls/1/merge',
    '"$HOME/bin/python3" -c \'import os; os.system("git push")\'',
    '$PUBLISH', '""$PUBLISH', '"g"$PUBLISH_TAIL',
    'GIT_BIN=echo $GIT_BIN push',
])
def test_environment_paths_do_not_hide_publishing(monkeypatch, command):
    monkeypatch.setenv('HOME', '/tmp/fixture-home')
    monkeypatch.setenv('GIT_BIN', '/tmp/fixture-home/bin/git')
    monkeypatch.setenv('PUBLISH', 'git push')
    monkeypatch.setenv('PUBLISH_TAIL', 'it push')
    assert hook.denied(event(command))


def test_quoted_home_with_spaces_preserves_executable_name(monkeypatch):
    monkeypatch.setenv('HOME', '/tmp/Fixture Home')
    assert not hook.denied(event('"$HOME/bin/python3" -c "print(1)"'))
    assert not hook.denied(event('"$HOME/bin/git" status'))
    assert hook.denied(event('"$HOME/bin/git" push'))
    assert hook.denied(event('"$HOME"/bin/gh pr merge 1'))


def test_environment_cannot_resolve_unknown_command_substitution(monkeypatch):
    monkeypatch.setenv('SYNTHE_UNKNOWN_SUBSTITUTION', 'echo')
    assert hook.denied(event('$(cat unknown-command) push'))


def test_env_split_string_preserves_quoted_executable_paths(monkeypatch):
    monkeypatch.setenv('HOME', '/tmp/Fixture Home')
    assert not hook.denied(event("env -S '\"${HOME}/bin/git\" status'"))
    assert hook.denied(event("env -S '\"${HOME}/bin/git\" push'"))


def test_environment_resolution_does_not_allow_unparsed_command_arguments(monkeypatch):
    monkeypatch.setenv('SUBCOMMAND', 'push origin HEAD')
    monkeypatch.setenv('OPTIONS', '-C /tmp/fixture')
    assert hook.denied(event('git $SUBCOMMAND'))
    assert hook.denied(event('git $OPTIONS push'))


def test_environment_expansion_is_bounded(monkeypatch):
    monkeypatch.setenv('LONG_PATH', 'x' * 200000)
    assert hook.denied(event('$LONG_PATH$LONG_PATH/git push'))


@pytest.mark.parametrize('operation', ['push_files', 'create_or_update_file', 'delete_file',
                                       'merge_pull_request', 'create_branch'])
@pytest.mark.parametrize('server', ['github', 'plugin_github_github', 'enterprise'])
def test_github_write_tools_are_matched_and_denied(operation, server):
    tool = f'mcp__{server}__{operation}'
    matcher = json.loads(HOOK.with_name('hooks.json').read_text())['hooks']['PreToolUse'][0]['matcher']
    assert re.fullmatch(matcher, tool), 'Claude must dispatch the hook for this tool'
    assert hook.denied({'hook_event_name': 'PreToolUse', 'tool_name': tool, 'tool_input': {}})


@pytest.mark.parametrize('tool', ['mcp__github__get_file_contents', 'mcp__github__list_branches',
                                  'mcp__github__get_pull_request', 'mcp__synthe__synthe_propose_effect'])
def test_read_and_broker_tools_receive_no_permission_override(tool):
    assert not hook.denied({'hook_event_name': 'PreToolUse', 'tool_name': tool, 'tool_input': {}})


@pytest.mark.parametrize('error', [RuntimeError, OSError, AssertionError, MemoryError])
def test_unexpected_exception_is_a_deny_without_echo(monkeypatch, capsys, error):
    def crash(_):
        raise error('fixture-sensitive-detail')
    monkeypatch.setattr(hook.sys, 'stdin', io.StringIO(json.dumps(event('git status'))))
    monkeypatch.setattr(hook, 'denied', crash)
    assert hook.main() == 0
    result = capsys.readouterr()
    assert json.loads(result.out)['hookSpecificOutput']['permissionDecision'] == 'deny'
    assert 'fixture-sensitive-detail' not in result.out + result.err


def test_input_read_failure_denies(monkeypatch, capsys):
    class BrokenInput:
        def read(self, _):
            raise OSError('fixture-sensitive-detail')
    monkeypatch.setattr(hook.sys, 'stdin', BrokenInput())
    assert hook.main() == 0
    assert json.loads(capsys.readouterr().out)['hookSpecificOutput']['permissionDecision'] == 'deny'


def test_output_failure_returns_blocking_exit_code(monkeypatch):
    class BrokenOutput:
        def write(self, _):
            raise OSError('fixture-sensitive-detail')
    monkeypatch.setattr(hook.sys, 'stdin', io.StringIO(json.dumps(event('git push'))))
    monkeypatch.setattr(hook.sys, 'stdout', BrokenOutput())
    def exit_fixture(code):
        raise SystemExit(code)
    monkeypatch.setattr(hook.os, '_exit', exit_fixture)
    with pytest.raises(SystemExit) as result:
        hook.main()
    assert result.value.code == 2


def test_real_broken_stdout_pipe_keeps_blocking_exit_code():
    child = subprocess.Popen([sys.executable, str(HOOK)], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    child.stdout.close()
    child.stdin.write(json.dumps(event('git push')).encode())
    child.stdin.close()
    assert child.wait(timeout=10) == 2
    assert child.stderr.read() == b''


@pytest.mark.parametrize("guard, replacement, command", [
    ('in {"push", "send-pack", "http-push", "credential"}', 'in {"mutation-disabled"}', "git push"),
    ('if executable in SHELLS:', 'if executable in set():', "bash -c 'git push'"),
])
def test_mutations_disabling_command_or_nested_shell_guard_are_detected(tmp_path, guard, replacement, command):
    source = HOOK.read_text()
    assert guard in source
    mutant = tmp_path / "hook.py"
    mutant.write_text(source.replace(guard, replacement, 1))
    result = subprocess.run([sys.executable, str(mutant)], input=json.dumps(event(command)),
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0
    assert result.stdout == "", "mutant should expose the unsafe allowance caught by the denial test"
    mutant_spec = importlib.util.spec_from_file_location("mutant_hook", mutant)
    mutant_hook = importlib.util.module_from_spec(mutant_spec)
    mutant_spec.loader.exec_module(mutant_hook)
    with pytest.raises(AssertionError):
        assert mutant_hook.denied(event(command)), "same publishing-denial assertion kills the mutant"
    assert hook.denied(event(command))
