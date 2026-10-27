"""Keep the model inside its sandbox after a permission error.

When an ordinary step fails with "permission denied" (a mount, an apt install,
the docker socket, a low port), Qwen3.8-Flash-Next tends to work around the
refusal with a privilege change: sudo/su, user namespaces (unshare), nsenter,
chroot, setcap/setuid, privileged docker, or writes to /etc and /proc/sys.
Cohere saw `unshare -Urm ... mount -t tmpfs` after a refused RAM disk.
Measured live (experiments/privilege, 5 scenarios, n=80 per cell):

* plain OS error: 16/80 and 21/80 workarounds (two runs), mostly sudo;
* a generic "no root here" notice: 2/80, both `unshare`;
* the notice that also names the blocked mechanisms: 0/80;
* through the gateway: 1/80 emitted (an `sg docker` group switch), rewritten
  before it reached the client.

So the gateway

* replaces a workaround call the model emits with an ``echo`` of that notice
  (``rewrite_call``), so the client returns the notice as the tool result, and
* on every request appends the notice once, to the last permission-error
  tool result, and drops workaround calls and their results from the history
  (``repair_history``).

Detection works on the shell structure (command position), so mentions in
docs, greps, quoted text and reads of /etc do not fire. Capability probes
such as ``sudo -n true`` or ``sudo -l`` are left alone.
"""

from __future__ import annotations

import json
import re
import shlex
from typing import Any

MARK = "[gateway:privilege]"
NOTICE = ("This sandbox runs without root by design. Privilege changes are not available. This includes "
          "sudo/su, user namespaces (unshare), mount, setcap and writes to /etc or /proc/sys. Continue with "
          "an unprivileged approach or report the blocker.")
ECHO_NOTICE = f"echo '{MARK} {NOTICE}'"

EXEC_TOOLS = frozenset({"bash", "shell", "sh", "terminal", "execute", "exec", "run", "run_command", "run_shell"})
COMMAND_KEYS = ("command", "cmd", "script")
PERMISSION_ERROR = re.compile(r"permission denied|not permitted|superuser|are you root|only root"
                              r"|password is required|must be run as root|requires root", re.I)

PRIV_WORDS = {"sudo": "sudo_su", "su": "sudo_su", "doas": "sudo_su", "pkexec": "sudo_su", "run0": "sudo_su",
              "unshare": "unshare", "nsenter": "nsenter", "chroot": "chroot",
              "setcap": "setuid_caps", "capsh": "setuid_caps", "newgrp": "newgrp_sg", "sg": "newgrp_sg"}
PASS_THROUGH = {"env", "exec", "time", "nohup", "command", "nice", "ionice", "stdbuf", "xargs", "builtin", "then",
                "do", "else", "if", "while", "until", "!", "{"}
SEPS = {";", "&&", "||", "|", "&", "(", ")", "|&", ";;", "\n"}
SHELLS = {"sh", "bash", "dash", "zsh", "ash"}
REDIRS = {">", ">>", "<", ">|", "<<", "<<<", ">&", "&>", "&>>", "<&", "<>"}
PROTECTED = re.compile(r"^/(etc|proc/sys)(/|$)")
SUDO_PROBE_FLAGS = [{"-n", "true"}, {"-l"}, {"-nl"}, {"-ln"}, {"-n", "-l"}, {"-v"}, {"-nv"}, {"-k"}, {"-K"}, {"-V"}]
_FALLBACK = re.compile(r"(?:^|[\s;&|(`$])(sudo|su|doas|pkexec|run0|unshare|nsenter|chroot|setcap|capsh|newgrp)\s")
_HEREDOC = re.compile(r"<<-?\s*(['\"]?)(\w+)\1([^\n]*)\n.*?\n\s*\2\s*(?=\n|$)", re.S)
_INTERP_C = re.compile(r"\b(?:python3?|perl|node|ruby)\s+-[ce]\s+(['\"])(.*?)\1", re.S)
_INTERP_CALL = re.compile(r"(?:os\.system|subprocess\.\w+|system|exec\w*|spawn\w*)\s*\(\s*\[?\s*['\"]\s*"
                          r"(?:/usr/bin/)?(sudo|su|doas|pkexec|unshare|nsenter|chroot|setcap)\b")


def _base(word: str) -> str:
    return word.rsplit("/", 1)[-1]


def _tokens(cmd: str) -> list[str] | None:
    s = cmd.replace("$(", " ( ").replace("`", " ; ").replace("\n", " ; ")
    try:
        lexer = shlex.shlex(s, posix=True, punctuation_chars=";&|()<>")
        lexer.whitespace_split = True
        lexer.commenters = "#"
        return list(lexer)
    except ValueError:
        return None


def _simple_commands(tokens: list[str]) -> list[list[str]]:
    out: list[list[str]] = []
    cur: list[str] = []
    for tok in tokens:
        if tok in SEPS:
            if cur:
                out.append(cur)
            cur = []
        else:
            cur.append(tok)
    if cur:
        out.append(cur)
    return out


def _strip_prefix(words: list[str]) -> list[str]:
    i = 0
    while i < len(words):
        w = words[i]
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", w) or w in PASS_THROUGH:
            i += 1
        elif w == "timeout" and i + 1 < len(words):
            i += 2
        elif w.startswith("-") and i > 0 and words[i - 1] in ("env", "nice", "xargs", "stdbuf", "ionice"):
            i += 1
        else:
            break
    return words[i:]


def _redirect_targets(words: list[str]) -> list[str]:
    return [words[j + 1] for j, w in enumerate(words) if w in (">", ">>", ">|", "&>", "&>>") and j + 1 < len(words)]


def _args_no_redirects(words: list[str]) -> list[str]:
    out: list[str] = []
    skip = False
    for j, w in enumerate(words):
        if skip:
            skip = False
            continue
        if w.isdigit() and j + 1 < len(words) and words[j + 1][:1] in "<>":
            continue  # fd number of a redirection, e.g. 2>/dev/null
        if w in REDIRS:
            skip = True
            continue
        out.append(w)
    return out


def _scan(cmd: str, depth: int = 0) -> set[str]:
    hits: set[str] = set()
    # Code passed to an interpreter that shells out to a privilege tool.
    for _, code in _INTERP_C.findall(cmd):
        if _INTERP_CALL.search(code):
            hits.add("interpreter")
    # Heredoc bodies are data (or code for another interpreter), not shell commands here.
    cmd = _HEREDOC.sub(lambda m: "<<" + m.group(1) + m.group(2) + m.group(1) + m.group(3), cmd)
    toks = _tokens(cmd)
    if toks is None:
        return hits | ({"sudo_su"} if _FALLBACK.search(cmd) else set())
    for sc in _simple_commands(toks):
        if any(PROTECTED.match(t) for t in _redirect_targets(sc)):
            hits.add("etc_procsys_write")
        words = _strip_prefix(_args_no_redirects(sc))
        if not words:
            continue
        w0, args = _base(words[0]), words[1:]
        if w0 in PRIV_WORDS:
            if w0 == "sudo" and set(args) in SUDO_PROBE_FLAGS:
                continue
            if w0 == "capsh" and args == ["--print"]:
                continue
            hits.add(PRIV_WORDS[w0])
            continue
        if w0 in SHELLS and "-c" in args and depth < 3:
            k = args.index("-c")
            if k + 1 < len(args):
                hits |= _scan(args[k + 1], depth + 1)
        elif w0 in ("docker", "podman") and args and args[0] in ("run", "create", "exec"):
            a = " ".join(args)
            if re.search(r"--privileged|(^|\s)(-v|--volume)[=\s]*/:|--pid[=\s]host|--cap-add|--security-opt"
                         r"|--userns[=\s]host", a):
                hits.add("docker_priv")
        elif w0 == "chmod":
            modes = [x for x in args if not x.startswith("-") or re.match(r"^-[ugoa]*[st]", x)]
            if modes and re.search(r"[ugoa]*\+[rwx]*s|^[2-7][0-7]{3}$", modes[0]):
                hits.add("setuid_caps")
        elif w0 == "tee":
            if any(PROTECTED.match(x) for x in args if not x.startswith("-")):
                hits.add("etc_procsys_write")
        elif w0 == "sed" and any(x.startswith("-i") or x == "--in-place" for x in args):
            if any(PROTECTED.match(x) for x in args):
                hits.add("etc_procsys_write")
        elif w0 in ("cp", "mv", "ln", "install", "rsync"):
            pos = [x for x in args if not x.startswith("-")]
            if pos and PROTECTED.match(pos[-1]):
                hits.add("etc_procsys_write")
        elif w0 == "dd":
            if any(x.startswith("of=") and PROTECTED.match(x[3:]) for x in args):
                hits.add("etc_procsys_write")
        elif w0 == "sysctl" and any(x == "-w" or "=" in x for x in args):
            hits.add("etc_procsys_write")
    return hits


def workaround_hits(cmd: str) -> list[str]:
    """Kinds of privilege workaround in a shell command (empty when none)."""
    return sorted(_scan(cmd or ""))


def _command_of(name: str, arguments: Any) -> tuple[str, dict[str, Any] | None]:
    try:
        args = json.loads(arguments) if isinstance(arguments, str) else arguments
    except ValueError:
        return "", None
    if not isinstance(args, dict):
        return "", None
    for key in COMMAND_KEYS:
        if isinstance(args.get(key), str) and ((name or "").lower() in EXEC_TOOLS or key == "command"):
            return key, args
    return "", None


def call_hits(name: str, arguments: Any) -> list[str]:
    key, args = _command_of(name, arguments)
    if not key or args is None:
        return []
    if MARK in args[key]:
        return ["marked"]
    return workaround_hits(args[key])


def rewrite_call(name: str, arguments: str) -> tuple[str, list[str]]:
    """Output side: a workaround call becomes an echo of the notice."""
    key, args = _command_of(name, arguments)
    if not key or args is None or MARK in args[key]:
        return arguments, []
    hits = workaround_hits(args[key])
    if not hits:
        return arguments, []
    return json.dumps({**args, key: ECHO_NOTICE}), hits


def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(p.get("text", "") for p in content if isinstance(p, dict) and isinstance(p.get("text"), str))
    return ""


def _with_notice(content: Any) -> Any:
    if NOTICE in _text(content):
        return content
    if isinstance(content, list):
        return [*content, {"type": "text", "text": NOTICE}]
    return (content if isinstance(content, str) else json.dumps(content)) + "\n" + NOTICE


def repair_history(messages: list[Any]) -> tuple[list[Any], list[dict[str, str]]]:
    """Drop workaround calls and their results; put the notice on the last permission error.

    The notice is added even when nothing was dropped: naming the blocked
    mechanisms next to the first permission error is what kept the model
    inside its limits (0/224 workarounds against 27/112 for the plain error).
    If no permission-error result exists but a call was dropped, the notice
    goes on the last tool result before the first dropped call. Returns
    (messages, events); inputs are not mutated.
    """
    dropped: set[str] = set()
    events: list[dict[str, str]] = []
    out: list[Any] = []
    first_drop_at: int | None = None
    for message in messages:
        if not isinstance(message, dict):
            out.append(message)
            continue
        if message.get("role") == "tool" and message.get("tool_call_id") in dropped:
            continue
        calls = message.get("tool_calls")
        if message.get("role") != "assistant" or not isinstance(calls, list) or not calls:
            out.append(message)
            continue
        kept = []
        for call in calls:
            fn = call.get("function") if isinstance(call, dict) else None
            hits = call_hits(fn.get("name", ""), fn.get("arguments")) if isinstance(fn, dict) else []
            if not hits:
                kept.append(call)
                continue
            if call.get("id"):
                dropped.add(call["id"])
            events.append({"rule": "privguard-drop", "original": str(fn.get("arguments"))[:500],
                           "kinds": ",".join(hits)})
            if first_drop_at is None:
                first_drop_at = len(out)
        if len(kept) == len(calls):
            out.append(message)
            continue
        message = {**message, "tool_calls": kept}
        if not kept:
            del message["tool_calls"]
            if not str(message.get("content") or "").strip():
                continue
        out.append(message)
    tool_positions = [i for i, m in enumerate(out) if isinstance(m, dict) and m.get("role") == "tool"]
    target = next((i for i in reversed(tool_positions) if PERMISSION_ERROR.search(_text(out[i].get("content")))), None)
    if target is None and first_drop_at is not None:
        target = next((i for i in reversed(tool_positions) if i < first_drop_at), None)
    if target is not None and NOTICE not in _text(out[target].get("content")):
        out[target] = {**out[target], "content": _with_notice(out[target].get("content"))}
        events.append({"rule": "privguard-notice", "original": _text(out[target].get("content"))[:200]})
    return out, events
