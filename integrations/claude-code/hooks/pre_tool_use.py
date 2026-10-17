#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Best-effort publishing guard, not a shell sandbox. The OS/credential wall is the enforcement boundary.

No command text is executed, logged or reflected into the response. Invalid hook input denies.
"""
import ast
import json
import os
import re
import shlex
import sys

MAX_INPUT = 256_000
MAX_DEPTH = 12
SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
GITHUB_WRITES = {"push_files", "create_or_update_file", "delete_file", "merge_pull_request", "create_branch"}
DENIAL = json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
    "permissionDecisionReason": "Synthe: use synthe_propose_effect for publishing. Approval belongs in the human's account. Invalid hook inputs are refused."}})


class Word(str):
    """Keep quoted whitespace in an executable path, including an expanded HOME."""
    def __new__(cls, value, quoted=False):
        result = super().__new__(cls, value)
        result.quoted = quoted
        return result


def _substitution(source, start, closing):
    """Find a nested substitution without executing or expanding any input."""
    level, quote, i = 1, "", start
    while i < len(source):
        char = source[i]
        if char == "\\" and quote != "'":
            i += 2
            continue
        if quote:
            if char == quote:
                quote = ""
        elif char in "'\"":
            quote = char
        elif char == closing:
            level -= 1
            if not level:
                return source[start:i], i + 1
        elif closing == ")" and char == "(":
            level += 1
        i += 1
    raise ValueError("unterminated substitution")


def _lex(source, depth, variables):
    """Small shell lexer: preserve command boundaries, discard comments, collect heredocs.

    Quote removal is lexical only. Executing substitutions are checked recursively; single
    quoted data is never inspected as code. Unsupported syntax is refused by the caller.
    """
    tokens, pending, word = [], [], []
    active = quoted = split_expansion = False
    quote = ""
    delimiter = None
    i = 0

    def emit():
        nonlocal active, quoted, split_expansion, delimiter
        if active:
            value = "".join(word)
            if delimiter is not None:
                doc = {"body": "", "expand": not quoted}
                tokens.append(("here", doc))
                pending.append((value, delimiter == "<<-", doc))
                delimiter = None
            else:
                tokens.append(("word", Word(value, quoted and not split_expansion)))
            word.clear()
            active = quoted = split_expansion = False

    while i < len(source):
        char = source[i]
        if char == "\\" and quote != "'":
            if i + 1 >= len(source):
                raise ValueError("trailing escape")
            if quote == '"' and source[i + 1] not in '$`"\\\n':
                word.append("\\")
                i += 1
                continue
            if source[i + 1] != "\n":
                word.append(source[i + 1])
                active = quoted = True
            i += 2
            continue
        if char == "'" and quote != '"' or char == '"' and quote != "'":
            quote = "" if quote == char else char
            active = quoted = True
            i += 1
            continue
        if quote != "'" and (source.startswith("$(", i) or char == "`"):
            offset, closing = (2, ")") if char == "$" else (1, "`")
            code, i = _substitution(source, i + offset, closing)
            if _shell_denied(code, depth + 1, variables):
                raise ValueError("publishing substitution")
            # Unsupported expansion syntax cannot be supplied by os.environ.
            word.append("${!SYNTHE_UNKNOWN_SUBSTITUTION}")
            active = True
            continue
        if not quote and char == "#" and not active:
            end = source.find("\n", i)
            i = len(source) if end < 0 else end
            continue
        if not quote and char in " \t\r\n;&|()<>":
            emit()
            if char in " \t\r":
                i += 1
                continue
            if source.startswith("<<", i):
                delimiter = "<<-" if source.startswith("<<-", i) else "<<"
                i += len(delimiter)
                continue
            if char in "<>" and source.startswith(char + "&", i):
                tokens.append(("op", char + "&"))
                i += 2
                continue
            tokens.append(("op", char))
            i += 1
            if char == "\n" and pending:
                for marker, strip_tabs, doc in pending:
                    lines = []
                    while i < len(source):
                        end = source.find("\n", i)
                        end = len(source) if end < 0 else end + 1
                        line = source[i:end]
                        i = end
                        compared = line.lstrip("\t") if strip_tabs else line
                        if compared.rstrip("\n") == marker:
                            doc["body"] = "".join(lines)
                            break
                        lines.append(compared)
                    else:
                        raise ValueError("missing heredoc delimiter")
                pending.clear()
            continue
        if char == "$" and not quote:
            split_expansion = True
        word.append(char)
        active = True
        i += 1
    emit()
    if quote or delimiter or pending:
        raise ValueError("incomplete shell command")
    return tokens


def _expand(word, variables, *, environment=False):
    size = len(word)
    def replace(match):
        nonlocal size
        name = match.group(1) or match.group(2)
        if name in variables:
            value = variables[name]
        elif environment and name in os.environ:
            value = os.environ[name]
        else:
            raise ValueError("unresolved command variable")
        size += len(value) - len(match.group(0))
        if size > MAX_INPUT:
            raise ValueError("command expansion too large")
        return value
    for _ in range(MAX_DEPTH):
        size = len(word)
        expanded = re.sub(r"\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)", replace, word)
        if expanded == word:
            if "$" in word:
                raise ValueError("unsupported command expansion")
            return expanded
        word = expanded
    raise ValueError("recursive command variable")


def _python_denied(source, depth, variables):
    if depth > MAX_DEPTH:
        return True
    tree = ast.parse(source)
    runners = {"subprocess.run", "subprocess.call", "subprocess.check_call",
                             "subprocess.check_output", "subprocess.Popen", "os.system", "os.popen"}
    aliases = {"subprocess": "subprocess", "os": "os"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module in {"subprocess", "os"}:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = ast.unparse(node.func)
        first, _, rest = name.partition(".")
        name = aliases.get(first, first) + ("." + rest if rest else "")
        if name in {"exec", "eval"}:
            if not node.args:
                return True
            value = ast.literal_eval(node.args[0])
            if not isinstance(value, str) or _python_denied(value, depth + 1, variables):
                return True
        if name.startswith(("os.exec", "os.spawn")):
            return True  # Multiple argv conventions: defer these executors to the broker.
        if name in runners:
            argument = node.args[0] if node.args else next(
                (kw.value for kw in node.keywords if kw.arg == "args"), None)
            if isinstance(argument, ast.Name):
                return True  # Runtime data flow is not a static publishing proof.
            else:
                value = ast.literal_eval(argument)
            if isinstance(value, str):
                if _shell_denied(value, depth + 1, variables):
                    return True
            elif isinstance(value, (list, tuple)) and all(isinstance(v, str) for v in value):
                if _command_denied(list(value), [], variables, depth + 1):
                    return True
            else:
                return True
    return False


def _command_denied(words, docs, variables, depth):
    if depth > MAX_DEPTH:
        return True
    assignments = {}
    while words and re.match(r"^[A-Za-z_]\w*=", words[0]):
        key, value = words.pop(0).split("=", 1)
        assignments[key] = value
    if not words:
        variables.update(assignments)
        return False
    if assignments:
        # Prefix assignments don't control expansion of this command's argv, but
        # can control a nested shell's environment. Check both views conservatively.
        return (_command_denied(list(words), docs, dict(variables), depth + 1)
                or _command_denied(list(words), docs, {**variables, **assignments}, depth + 1))
    if words[0] in {"if", "then", "elif", "else", "while", "until", "do", "!", "time", "{"}:
        return _command_denied(words[1:], docs, variables, depth + 1)
    command_word = words.pop(0)
    executable = _expand(command_word, variables, environment=True)
    # Unquoted variables can supply both the executable and its arguments.
    pieces = [executable] if getattr(command_word, "quoted", False) else executable.split()
    executable = pieces[0].rsplit("/", 1)[-1]
    words = pieces[1:] + words
    if executable in {"env", "command", "exec", "builtin", "nohup", "sudo", "nice", "timeout", "xargs"}:
        if executable == "command" and any(word in {"-v", "-V"} for word in words):
            return False
        while words and words[0].startswith("-"):
            flag = words.pop(0)
            if executable == "env" and (flag == "-S" or flag.startswith(("--split-string", "-S"))):
                if flag in {"-S", "--split-string"}:
                    if not words:
                        return True
                    command = words.pop(0)
                else:
                    command = flag.split("=", 1)[1] if flag.startswith("--") else flag[2:]
                split_words = [Word(part, quoted=True) for part in shlex.split(command)]
                return _command_denied(split_words + words, docs, variables, depth + 1)
            if executable == "env" and flag in {"-u", "--unset", "-C", "--chdir"} and words:
                words.pop(0)
            elif executable in {"exec", "env"} and flag in {"-a", "--argv0"} and words:
                words.pop(0)
            elif executable in {"sudo", "nice", "timeout", "xargs"} and flag in {
                    "-u", "-g", "-n", "-s", "-k", "-I", "-P", "-d", "-E", "-L", "-a",
                    "--user", "--signal", "--delimiter", "--arg-file", "--max-args", "--max-procs",
                    "--max-lines", "--max-chars", "--eof", "--replace"} and words:
                words.pop(0)
            elif executable == "sudo" and flag in {"-h", "-p", "-D", "-R", "-T",
                    "--host", "--prompt", "--chdir", "--chroot", "--command-timeout"} and words:
                words.pop(0)
            elif executable == "timeout" and flag == "--kill-after" and words:
                words.pop(0)
            elif executable == "nice" and flag == "--adjustment" and words:
                words.pop(0)
        if executable == "timeout" and words:
            words.pop(0)
        return _command_denied(words, docs, variables, depth + 1)
    if executable in SHELLS:
        for i, word in enumerate(words):
            if re.fullmatch(r"-[A-Za-z]+", word) and "c" in word[1:]:
                return i + 1 >= len(words) or _shell_denied(words[i + 1], depth + 1, variables)
        return any(_shell_denied(doc["body"], depth + 1, variables) for doc in docs)
    if executable == "eval":
        return _shell_denied(" ".join(words), depth + 1, variables)
    if executable == "git":
        while words and words[0].startswith("-"):
            option = words.pop(0)
            if option in {"-c", "-C", "--git-dir", "--work-tree", "--namespace", "--config-env"} and words:
                words.pop(0)
        return bool(words) and _expand(words[0], variables) in {"push", "send-pack", "http-push"}
    if executable == "gh":
        while words and words[0].startswith("-"):
            option = words.pop(0)
            if option in {"-R", "--repo", "--hostname"} and words:
                words.pop(0)
        args = [_expand(word, variables) for word in words[:2]]
        return bool(args) and (args[0] == "api" or args[:2] in [
            ["pr", "merge"], ["repo", "sync"], ["release", "create"], ["release", "upload"],
            ["release", "edit"], ["release", "delete"]])
    if executable in {"curl", "wget", "http", "https", "xh"}:
        return any("api.github.com" in _expand(word, variables).lower() for word in words)
    if re.fullmatch(r"python(?:[23](?:\.\d+)?)?", executable):
        if "-c" in words:
            i = words.index("-c")
            return i + 1 >= len(words) or _python_denied(words[i + 1], depth + 1, variables)
        return any(_python_denied(doc["body"], depth + 1, variables) for doc in docs)
    return False


def _shell_denied(source, depth=0, variables=None):
    if depth > MAX_DEPTH:
        return True
    variables = dict(variables or {})
    words, docs = [], []
    redirect = False
    for kind, value in _lex(source, depth, variables):
        if kind == "word":
            if redirect:
                redirect = False
            else:
                words.append(value)
        elif kind == "here":
            docs.append(value)
            if value["expand"]:
                # Only expansions execute in data heredocs. Their remaining text is data.
                _lex('"' + value["body"].replace('"', '\\"') + '"', depth + 1, variables)
        elif value in ";&|()\n":
            if _command_denied(words, docs, variables, depth):
                return True
            words, docs = [], []
            redirect = False
        elif value in {"<", ">", "<&", ">&"}:
            # Redirection destinations are data, but substitutions were already checked.
            if words and (words[-1].isdigit() or re.fullmatch(r"\{[A-Za-z_]\w*\}", words[-1])):
                words.pop()
            redirect = True
    return _command_denied(words, docs, variables, depth)


def denied(event):
    if not isinstance(event, dict) or event.get("hook_event_name") != "PreToolUse":
        return True
    tool = event.get("tool_name")
    if not isinstance(tool, str):
        return True
    if tool.endswith(("__synthe_submit_approval", "__github_publish")):
        return True
    if tool.startswith("mcp__") and tool.rsplit("__", 1)[-1] in GITHUB_WRITES:
        return True
    if tool != "Bash":
        return False
    params = event.get("tool_input")
    if not isinstance(params, dict) or not isinstance(params.get("command"), str):
        return True
    try:
        return _shell_denied(params["command"])
    except (ValueError, TypeError, SyntaxError, RecursionError, IndexError):
        return True


def main():
    try:
        raw = sys.stdin.read(MAX_INPUT + 1)
        block = len(raw) > MAX_INPUT or denied(json.loads(raw))
    except Exception:
        block = True
    if block:
        try:
            print(DENIAL, flush=True)
        except Exception:
            # Avoid a second failed stdout flush at interpreter shutdown changing
            # this blocking exit code into Python's non-blocking-for-Claude 120.
            os._exit(2)
    # No allow decision: leave every other Claude permission check intact.
    return 0


if __name__ == "__main__":
    sys.exit(main())
