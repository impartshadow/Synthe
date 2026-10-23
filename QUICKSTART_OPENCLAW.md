# Quickstart: your first approved push (macOS, OpenClaw)

You start with a Mac and a GitHub repo. You finish with one commit that an OpenClaw agent wrote, you
read and approved, and Synthe pushed to GitHub.

How it works:
- The agent runs in its own Mac account (`openclaw`) and has no GitHub login.
- A hidden `_synthe` user holds the only GitHub token.
- Synthe pushes only a commit you approved, and writes a signed receipt for it.

macOS on Apple silicon is the verified platform. These steps match what was run on 2026-10-07
([`docs/OPENCLAW_RESULTS.md`](docs/OPENCLAW_RESULTS.md)), but nobody has timed them with a new user
yet. Not on a Mac, or not using OpenClaw? See [`docs/ANY_AGENT.md`](docs/ANY_AGENT.md).

## Before you start

You need:
- **A Mac account with admin rights.** You'll type your Mac password once.
- **A GitHub repo** for the agent to work on, private or public. Agent work lands only on `agent/*`
  branches, and only after you approve it.
- **A fine-grained GitHub token for that one repo.** On GitHub go to Settings → Developer settings →
  Personal access tokens → Fine-grained tokens → Generate new token. Under Repository access choose
  **Only select repositories** and pick the repo. Under Permissions set **Contents: Read and write**.
  Copy the token (it starts with `github_pat_`). You'll paste it once, hidden, in step 5.
- **An API key for the model OpenClaw will use**, for step 6.

Open Terminal (Applications → Utilities → Terminal). Each step below is one command; paste it and
press Return.

## 1. Install Homebrew (skip if you have it)

```bash
brew --version
```

If that prints `Homebrew 4.x` or similar, go to step 2. If it says `command not found`, install it:

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

Follow what it prints at the end. It asks you to run two lines that add `brew` to your PATH. Then
`brew --version` should work.

## 2. Get Synthe

```bash
git clone https://github.com/rohansiddam/Synthe ~/synthe && cd ~/synthe
```

If macOS asks to install the command line developer tools, accept, wait for it to finish, and run
the line again.

**You should see:** `Cloning into '/Users/<you>/synthe'...`. Run every later command from this
`~/synthe` folder unless a step says otherwise. There's no one-line installer yet: a tagged release
comes first, so cloning is the install for now.

## 3. Install

```bash
brew install python node git && PY=$(bash deploy/macos/find-python.sh) && "$PY" -m venv ~/synthe-venv && ~/synthe-venv/bin/pip install -q .
```

This builds Synthe its own Python environment in `~/synthe-venv`. `find-python.sh` picks a Python
that really works: Homebrew's newest Python can be installed but broken on an older macOS.

If it says no working Python was found, run what it prints (usually `brew install python@3.13`), then
run the same line again.

**Check:**

```bash
ls ~/synthe-venv/bin/synthe-init
```

**You should see:** `/Users/<you>/synthe-venv/bin/synthe-init`

## 4. Prepare

Put in your repo's URL. `--allowed-paths` lists the files the agent may change; `'src/**'` means
everything under `src/`.

```bash
~/synthe-venv/bin/synthe-init prepare --repo-url https://github.com/YOU/REPO.git --allowed-paths 'src/**'
```

It checks the Mac, needs no secrets, and writes the script for step 5.

**You should see:** a `PASS  preflight checks passed` line, then:

```
bash /Users/<you>/.synthe/finish-setup.sh
```

If it says `can't prepare yet:` instead, fix each item it lists (for example `brew install node`) and
run the line again.

## 5. Finish setup (you type the secrets)

```bash
bash ~/.synthe/finish-setup.sh
```

It asks for three things, in this order:
1. a new **approval passphrase**, twice. Pick a new one and remember it: it signs every approval.
2. your **GitHub token**. Paste it; nothing shows as you paste.
3. your **Mac password**, once, for the admin step.

Then it does the rest by itself:
- creates the agent's Mac account `openclaw`;
- installs the broker as the hidden `_synthe` user;
- installs OpenClaw in the agent's account, with the Synthe plugin, skill and gateway;
- clones your repo there through the broker, so the agent's account needs no GitHub access, not
  even to read;
- runs the doctor.

**You should see:** the doctor's report near the end, with the level **ENFORCED** and every check
`PASS`. Its last lines suggest OpenClaw's setup wizard; skip that and use step 6.

If the level isn't ENFORCED, stop here: the failing check says what's wrong.

## 6. Give OpenClaw a model and start it (agent's account)

Setup already runs OpenClaw's gateway as a service in the agent's account. Switch to that account and
add your model key:

```bash
sudo -iu openclaw
export PATH="$HOME/.local/bin:/opt/homebrew/bin:$PATH"
openclaw models auth add
```

Pick your provider and paste your API key. Then start the chat:

```bash
cd ~/repo && openclaw tui
```

**You should see:** a title bar showing `ws://127.0.0.1:...` (the gateway). If it says local or
embedded instead, quit and run `openclaw tui` again without `--local`: in embedded mode the Synthe
plugin doesn't run, and only the missing credentials stop a push.

Leave this window open. It's the agent's window.

## 7. Give OpenClaw a task (your account)

Open a **new** Terminal window (⌘N). It runs as you, not as `openclaw`.

```bash
cd ~/synthe && ~/synthe-venv/bin/synthe-task new "Add a greeting and test it" --branch agent/first-push
```

Type your approval passphrase.

**You should see:** a `PASS` line for `signed with your key` and `agent/first-push`, then a **Tell OpenClaw**
paragraph. Copy that paragraph and paste it into the agent's window from step 6.

OpenClaw checks the task, commits on `agent/first-push` and proposes the push through Synthe. It
can't push by itself.

## 8. Read the diff and approve (your account)

When OpenClaw says the push is **staged**, run this in your window:

```bash
SYNTHE_BROKER=unix:///var/db/synthe-run/broker.sock ~/synthe-venv/bin/synthe-approve
```

The diff it shows is the broker's own copy of the commit, not the agent's description of it.

- Read it. A push that is large, deletes files, or touches CI, dependency or secrets-like files is
  marked CHECK or HIGH-RISK. For a high-risk push you type the last 4 characters of the commit first.
  A long diff has to be viewed in full (`v`) before you can approve.
- Press `a` to approve, then type your approval passphrase.

**You should see:**

```
 Approval: approval_accepted (receipt #N)
 Push: executed (receipt #M)  1a2b3c4d5e6f → agent/first-push
```

Your receipt numbers and commit will differ. Note the commit's first characters.

## Check: what you should see

From your own window, ask GitHub directly, outside Synthe:

```bash
git ls-remote https://github.com/YOU/REPO.git refs/heads/agent/first-push refs/heads/main
```

You're done when all four of these hold:
- [ ] `refs/heads/agent/first-push` exists, and its commit starts with the characters from step 8.
- [ ] `refs/heads/main` is the same commit it was before you started.
- [ ] The doctor in step 5 said **ENFORCED** with every check `PASS`.
- [ ] OpenClaw said it **proposed** the push and waited. It didn't push.

If the branch isn't there, run `synthe-approve` again: an unapproved proposal stays staged, and the
receipt numbers from step 8 tell you what the broker decided.

## Next

- **Approve with Touch ID.** Enroll a Secure Enclave key, then install the updated registry and code
  into the broker:

  ```bash
  ~/synthe-venv/bin/synthe-init touchid
  sudo bash deploy/macos/upgrade.sh
  ```

  Your passphrase key stays as the fallback (`synthe-approve --passphrase`). Read
  [`docs/TOUCHID.md`](docs/TOUCHID.md) first: Touch ID protects the approval key, but it doesn't
  decide whether a diff is safe.
- **Your approval history.** `synthe-approve --stats` shows your approval rate and time to decision,
  from a local log that never leaves your Mac (owner-only, last 1,000 decisions;
  `SYNTHE_APPROVALS_LOG=off` turns it off).
- **Attack your own install.** [`docs/REDTEAM.md`](docs/REDTEAM.md) runs 30 attacks plus 3 controls
  from the agent's account, with no model, and checks the receipts against the broker's published
  key.
- **Audit receipts without the broker:** [`docs/VERIFY.md`](docs/VERIFY.md).
- **Let your coding agent do steps 2 to 4:** point it at `skills/synthe-setup/SKILL.md`. Step 5 is
  always yours, because that's where the secrets are typed.

## What this does not claim

- **The plugin is a seatbelt, not the wall.** It works only through the gateway, and obfuscated
  commands or another git library can get past its text matching. The wall is credential custody:
  the agent's account has no GitHub token, `gh` login or SSH key that can push, and `doctor` checks
  that.
- **Synthe mediates git effects.** It doesn't stop prompt injection, and it doesn't judge whether
  the code you approve is correct.
