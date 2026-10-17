# synthe-barrier: Synthe's commit barrier for OpenClaw

Blocks recognized direct `git push` and GitHub-publish tool calls, and points the agent to Synthe instead: it
proposes the push, you approve it after reading the diff, and the Synthe broker pushes it exactly once
and writes a signed receipt. It also adds a one-line status to each turn: what waits for your
approval, and the latest receipt.

**This plugin needs Synthe.** On its own it only blocks pushes. Install Synthe first; its setup wires
in this plugin, the `synthe` skill, the MCP server and the gateway:
<https://github.com/rohansiddam/Synthe> (see `QUICKSTART_OPENCLAW.md`).

**It acts only through the OpenClaw gateway** (`openclaw tui`). `openclaw tui --local` and
`openclaw chat` skip plugins. It's a seatbelt, not the wall: the wall is that the agent's account
holds no GitHub credential, which `synthe-init doctor` checks.
Synthe does not prevent prompt injection or a person approving the wrong change. The broker controls
only the credentials and remotes configured for it.

Configuration: `brokerSocket` (the broker's address), `blockDirectPush` (default true), `statusLine`
(default true).

License: Apache-2.0.
