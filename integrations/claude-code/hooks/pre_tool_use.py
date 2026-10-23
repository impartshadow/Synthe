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
    if executable == "alias":
        # An alias body runs later as a command (`bash -c "alias p='git push'; p"`).
        return any(_shell_denied(word.split("=", 1)[1], depth + 1, variables) for word in words if "=" in word)
    if executable in {"git-push", "git-send-pack", "git-http-push"}:
        return True  # The dashed forms in git's exec-path, e.g. /usr/lib/git-core/git-send-pack.
    if executable == "eval":
        return _shell_denied(" ".join(words), depth + 1, variables)
    if executable == "git":
        while words and words[0].startswith("-"):
            option = words.pop(0)
            value = None
            if option in {"-c", "-C", "--git-dir", "--work-tree", "--namespace", "--config-env"} and words:
                value = words.pop(0)
            elif option.startswith(("-c", "--config-env=")):
                value = option.split("=", 1)[1] if option.startswith("--") else option[2:]
            # `git -c alias.p=push p` runs push under another name, so no alias is set from the command line.
            if value is not None and option != "-C" and _expand(value, variables).lower().startswith("alias."):
                return True
        if not words:
            return False
        subcommand = _expand(words[0], variables)
        # `git credential fill` prints the stored credential; the helpers are run as `git credential-<name>`.
        return subcommand in {"push", "send-pack", "http-push", "credential"} or subcommand.startswith("credential-")
    if executable == "gh":
        while words and words[0].startswith("-"):
            option = words.pop(0)
            if option in {"-R", "--repo", "--hostname"} and words:
                words.pop(0)
        args = _expand_values(words[:2], variables)
        if args[:2] in (["auth", "token"], ["auth", "git-credential"]):
            return True  # Prints or hands out the token.
        if args[:2] == ["auth", "status"]:
            return any(_expand(word, variables) in {"-t", "--show-token"} for word in words[2:])
        if args and args[0] == "api":
            return _gh_api_writes(_expand_values(words[1:], variables))
        # `gh pr create` can push an unpublished head branch itself (even with --dry-run), so it is denied.
        return bool(args) and args[:2] in [
            ["pr", "merge"], ["pr", "create"], ["repo", "sync"], ["release", "create"], ["release", "upload"],
            ["release", "edit"], ["release", "delete"]]
    if executable == "curl":
        expanded = _expand_values(words, variables)
        return any(_github_api_host(w) or "$" in w for w in expanded) and _curl_writes(expanded)
    if executable == "wget":
        expanded = _expand_values(words, variables)
        return any(_github_api_host(w) or "$" in w for w in expanded) and _wget_writes(expanded)
    if executable in {"http", "https", "xh"}:
        # httpie and xh send a body for any `key=value` item, so a call to the API is not checked further.
        return any(_github_api_host(_expand(word, variables)) for word in words)
    if re.fullmatch(r"python(?:[23](?:\.\d+)?)?", executable):
        if "-c" in words:
            i = words.index("-c")
            return i + 1 >= len(words) or _python_denied(words[i + 1], depth + 1, variables)
        return any(_python_denied(doc["body"], depth + 1, variables) for doc in docs)
    return False


# Only a call that evidently writes is denied (2026-10-22). The hook is a guard, not the boundary: the
# credential wall is. An earlier version let through only calls it could prove were reads, which blocked
# plain `curl -s https://api.github.com/...` and any unfamiliar option, and changed ordinary workflows.
# Writes stay denied in every spelling found in review: glued short options (`-sX POST`, `-sd`), config
# files (`-K`), bodies and fields that imply POST, a method override, GraphQL, and gh's `-H` taking the
# next token. Not covered: a ~/.curlrc that adds a body, and scripts the hook cannot read.
_CURL_WRITES = {"-d", "-F", "-T", "-K", "--data", "--data-ascii", "--data-binary", "--data-raw",
                "--data-urlencode", "--json", "--form", "--form-string", "--upload-file", "--config"}
_CURL_SHORT_VALUE = set("AbcCDeEHmoPQrtuUwxXyYz") | set("dFTK")
_CURL_LONG_VALUE = {"--header", "--output", "--write-out", "--max-time", "--connect-timeout", "--retry",
                    "--user-agent", "--url", "--user", "--referer", "--cookie", "--cookie-jar", "--proxy",
                    "--cacert", "--cert", "--key", "--resolve", "--range", "--dump-header", "--retry-delay",
                    "--retry-max-time", "--limit-rate", "--request"}
_GH_API_WRITES = {"-f", "-F", "--field", "--raw-field", "--input"}
_GH_API_SHORT_VALUE = set("HXqtpfF")
_GH_API_LONG_VALUE = {"--header", "--method", "--jq", "--template", "--preview", "--hostname", "--cache",
                      "--field", "--raw-field", "--input"}


def _expand_values(words, variables) -> list:
    """Expand what can be expanded. A word that only carries a value (`\"Bearer $GITHUB_TOKEN\"`, a URL)
    keeps an unknown variable as written; one that could become an option (`$OPTS` unquoted, `-s$X`) raises,
    so the command is denied. A kept `$` counts as a possible GitHub host and a possible GraphQL path."""
    out = []
    for word in words:
        try:
            out.append(_expand(word, variables))
        except ValueError:
            if word.startswith("-") or (word.startswith("$") and not getattr(word, "quoted", False)):
                raise
            out.append(str(word))
    return out


def _github_api_host(word) -> bool:
    # uploads.github.com takes release assets with the same token as the REST API.
    return any(host in word.lower() for host in ("api.github.com", "uploads.github.com"))


def _method_is_read(value) -> bool:
    return isinstance(value, str) and value.upper() in {"GET", "HEAD"}


def _options(args, short_value, long_value, honor_double_dash):
    """Yield (option, value) and (None, positional) the way the tool reads them. Short options may be
    combined (-sS), and the first one that takes a value takes the rest of the word or the next word
    (-sXPOST, -sX POST). A missing value yields (option, None)."""
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            if honor_double_dash:
                for rest in args[i + 1:]:
                    yield None, rest
                return
        elif a.startswith("--"):
            name, eq, val = a.partition("=")
            if not eq and name in long_value:
                i += 1
                val = args[i] if i < len(args) else None
            yield name, val if (eq or name in long_value) else None
        elif a.startswith("-") and len(a) > 1:
            for j in range(1, len(a)):
                flag = "-" + a[j]
                if a[j] in short_value:
                    val = a[j + 1:]
                    if not val:
                        i += 1
                        val = args[i] if i < len(args) else None
                    yield flag, val
                    break
                yield flag, None
        else:
            yield None, a
        i += 1


def _curl_writes(args) -> bool:
    for option, value in _options(args, _CURL_SHORT_VALUE, _CURL_LONG_VALUE, True):
        if option in _CURL_WRITES:
            return True
        if option in ("-X", "--request") and not _method_is_read(value):
            return True
    return False


def _graphql(endpoint) -> bool:
    endpoint = endpoint.split("?", 1)[0].split("#", 1)[0]
    if "://" in endpoint:
        endpoint = endpoint.partition("://")[2].partition("/")[2]
    path = endpoint.strip("/").lower()
    return path == "graphql" or path.endswith("/graphql")


def _gh_api_writes(args) -> bool:
    # `--` is not honoured here: anything after it is still checked, so `gh api x -- -X POST` stays denied.
    positional = []
    for option, value in _options(args, _GH_API_SHORT_VALUE, _GH_API_LONG_VALUE, False):
        if option is None:
            positional.append(value)
        elif option in _GH_API_WRITES:
            return True
        elif option in ("-X", "--method") and not _method_is_read(value):
            return True
    return not positional or any(_graphql(p) or re.search(r"\$\{?\w+\}?$", p) for p in positional)


def _wget_writes(args) -> bool:
    for a in args:
        name, _, value = a.partition("=")
        if name in {"--post-data", "--post-file", "--body-data", "--body-file"}:
            return True
        if name == "--method" and not _method_is_read(value):
            return True
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
