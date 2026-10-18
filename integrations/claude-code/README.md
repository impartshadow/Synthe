# Claude Code adapter

Preview; hook tests pass locally, a real Claude Code session is still a release acceptance check.
First complete [agent-neutral setup](../../docs/ANY_AGENT.md), then run Claude in the agent's separate
OS account. Put the installed Synthe executables on its PATH. Do not log in to GitHub in that account.

In the approver's own account this is **ADVISORY**: that account has a GitHub login, so Claude can
use those credentials directly. For **ENFORCED**, run Claude Code in the agent's separate account,
as with OpenClaw, and run doctor there. The hook and MCP configuration alone do not enforce it.

The plugin runs `synthe-mcp` with no address flag. It discovers `SYNTHE_BROKER`, then the broker in
`~/.synthe/setup.json`, then the standard daemon sockets (macOS, Linux, user-local). With the normal
macOS installation, no environment variable is required. An explicit `--broker-url` takes priority
when configuring MCP manually. `SYNTHE_BROKER_UID` still pins the kernel identity on every call.
If discovery or the startup hello fails, the server exits with one stderr line describing the fix.

On macOS:

```sh
export PATH="/Library/Synthe/venv/bin:$PATH"
claude --plugin-dir /absolute/path/to/integrations/claude-code
```

On Linux use `/opt/synthe/bin` and `unix:///run/synthe/broker.sock`. Keep the plugin in a trusted,
readable location outside the agent's project; do not run a plugin supplied by an untrusted repository.

The plugin bundles a local stdio MCP connection, a skill, and a `PreToolUse` hook. The hook rejects
recognizable pushes, merges, raw GitHub API commands, and delivery of approvals through MCP. Other
commands get no permission decision, preserving Claude's usual checks. Malformed input is refused.
It never echoes command text, which can contain secrets. Command boundaries and executable positions
are parsed: quoted mentions, comments and inert heredoc text can describe publishing commands.
Nested shell `-c`, `eval`, command substitutions, command variables and recognizable Python process
calls are checked too. A shell heredoc is code; a Python heredoc is inspected for process calls;
other heredocs are data, with executing substitutions still checked when their delimiter is unquoted.
Unresolved command variables, malformed syntax and excessive nesting fail closed. Actual `gh api`
commands remain blocked even for reads, as a deliberate adapter policy.

Limits: obfuscated commands, aliases, scripts, other publishing tools, and disabled hooks can bypass
this bounded parser. It does not supply credentials, sign approvals or replace account isolation.
Run `synthe-init doctor --repo ~/repo` **as the agent**. No ENFORCED claim from installing a plugin alone.

Format references (checked 2026-10-08): [Claude hooks](https://code.claude.com/docs/en/hooks),
[plugin layout](https://code.claude.com/docs/en/plugins-reference).
