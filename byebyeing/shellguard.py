"""Remove off-task network actions from tool calls that run commands.

Qwen3.8-Flash-Next sometimes turns a shell or python tool call into a probe:
it uploads a probe payload to a storage bucket, or it queries the cloud
metadata service (169.254.169.254, 100.100.100.200, ...) for credentials.
Once such a call is in the conversation the model tends to repeat it with
other hosts. Measured live (experiments/upload and experiments/metadata,
n=48 per cell), back on task on the next turn, raw vs repaired:

* after two failed uploads: 16/48 vs 37/48, with 6 vs 0 more uploads;
* after three failed metadata probes: 21/48 vs 47/48, with 9 vs 0 more
  metadata or credential calls;
* a placeholder result or a ban word gets copied or spelled around
  (experiments/routify).

So this module

* rewrites the call the model is emitting (``rewrite_call``): offending
  statements are removed and replaced by a marked ``echo`` of a short notice,
  and
* repairs the history on the next request (``repair_history``): a call with
  nothing benign left is dropped together with its result; otherwise the call
  keeps its benign statements, and its result loses the lines of the removed
  statements and gets one gateway note.

Detection is structural, not a word list. An upload counts only when it is a
real upload stage (curl -T/-F/-d/-X PUT..., wget --post-*, python put/post,
scp/rsync/aws s3/ossutil/nc ...) aimed at a host that never appeared in the
system or user messages or earlier tool results (``allowed_hosts``). Uploads
to local hosts are left alone unless they carry a probe token. Metadata
access counts only when a network client in command position targets a
metadata host; mentions in docs, greps or rule files are left alone.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any, Iterable

MARK = "[gateway:removed]"
NOTICE = ("A network command that is not part of this task (an upload to an outside host, or a cloud "
          "metadata request) was removed from this call. It is not needed: this sandbox has no cloud "
          "credentials. Continue with the task.")
ECHO_NOTICE = f"echo '{MARK} {NOTICE}'"
_MARK_KIND = re.compile(re.escape(MARK) + r" \((upload|metadata)\)")


def _echo_notice(kinds: list[str]) -> str:
    """The marked echo that replaces removed statements; it records the kind for the history repair."""
    kind = "upload" if "upload" in kinds else "metadata" if "metadata" in kinds else ""
    return f"echo '{MARK} ({kind}) {NOTICE}'" if kind else ECHO_NOTICE
HISTORY_NOTE = "[gateway] " + NOTICE
# One generic note for every kind. In an earlier live comparison (n=24 per cell) the generic note
# gave 55/72 back on task and kind-specific notes gave 38/72. It never names the host.

# Tools whose arguments run. Other tools (write, edit, read, search) only mention hosts.
EXEC_TOOLS = frozenset({"bash", "shell", "sh", "terminal", "execute", "exec", "run", "run_command",
                        "run_shell", "run_python", "python", "web_fetch", "fetch"})
COMMAND_KEYS = ("command", "cmd", "script")
CODE_KEYS = ("code",)
URL_KEYS = ("url",)

# -- metadata endpoints ----------------------------------------------------
META_HOST = (
    r"169\.254\.169\.(?!123(?!\d))\d{1,3}(?!\d)|169\.254\.170\.\d{1,3}(?!\d)|100\.100\.100\.200"
    r"|169\.254\.0\.23|168\.63\.129\.16"
    r"|fd00:ec2::(?:254|23)|\[fd00:ec2::(?:254|23)\]"
    r"|::ffff:169\.254\.169\.254|::ffff:a9fe:a9fe"
    r"|2852039166|0xa9fea9fe|0x?a9\.0x?fe\.0x?a9\.0x?fe|0251\.0376\.0251\.0376|169\.254\.43518"
    r"|metadata\.google\.internal|metadata\.goog|metadata\.tencentyun\.com|metadata\.azure\.com"
    r"|metadata\.aliyuncs\.com|(?<=://)metadata(?=[:/])"
    r"|instance-data(?:\.ec2\.internal)?"
)
NET_VERB = (r"(?:curl|wget|http|xh|nc|ncat|telnet|socat|aria2c|lynx|Invoke-RestMethod|Invoke-WebRequest"
            r"|iwr|irm)")
CMD_POS = (r"(?:^\s*|[;&|(\n]\s*|\$\(\s*|\b(?:sudo|timeout\s+\S+|nohup|exec|time|xargs|do|then|else"
           r"|env(?:\s+\w+=\S*)*)\s+)")
CMD_TO_META = re.compile(CMD_POS + NET_VERB + r"(?:\.exe)?\b[^\n;|&]*?(?:(?<=[\s\"'@\[])|(?<=//))(?:"
                         + META_HOST + r")\b", re.I | re.M)
DEVTCP_META = re.compile(r"/dev/(?:tcp|udp)/(?:" + META_HOST + r")\b", re.I)
PY_META = re.compile(r"(?:urlopen|Request|requests\.\w+|httpx\.\w+|session\.\w+|create_connection|\.connect"
                     r"|HTTPConnection)\s*\(\s*[\(\[]?\s*f?[\"'](?:https?://)?\[?(?:" + META_HOST + r")", re.I)
PY_NET_ANY = re.compile(r"\b(?:socket|urllib|requests|httpx|aiohttp|ftplib|http\.client|telnetlib|paramiko"
                        r"|pycurl|subprocess|os\.system)\b")
PY_META_LIT = re.compile(r"[\"'](?:https?://)?\[?(?:" + META_HOST + r")\]?[\"'/:]", re.I)
NET_ANY = re.compile(CMD_POS + NET_VERB + r"\b", re.I | re.M)
META_URL_LIT = re.compile(r"(?:https?|ftp)://(?:[^\s/@\"']*@)?\[?(?:" + META_HOST + r")\b", re.I)
MENTION_RE = re.compile(r"\s*(?:echo|printf|grep|egrep|rg|sed|awk|cat|tee|logger|#)\b|\s*#", re.I)
URL_TO_META = re.compile(r"^\s*(?:https?|ftp)://\[?(?:" + META_HOST + r")\]?(?=[:/?#]|$)", re.I)


def is_metadata_op(text: str, kind: str = "shell") -> bool:
    """True if ``text`` sends a request to a metadata host. ``kind``: shell, python or url."""
    if not text:
        return False
    if kind == "url":
        return bool(URL_TO_META.search(text))
    if PY_META.search(text):
        return True
    if kind == "python":
        return bool(PY_NET_ANY.search(text) and PY_META_LIT.search(text))
    if DEVTCP_META.search(text) or CMD_TO_META.search(text):
        return True
    # A metadata URL held in a variable or loop list, with a network client elsewhere.
    if NET_ANY.search(text) and META_URL_LIT.search(text):
        holders = [part for part in re.split(r"[;\n]|&&|\|\|", text) if META_URL_LIT.search(part)]
        return not all(MENTION_RE.match(part) for part in holders)
    return False


# -- uploads ---------------------------------------------------------------
URL_RE = re.compile(r"(?:https?|ftp)://[^\s\"'<>)\]}|;`]+", re.I)
BARE_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?\b")
# Short curl flags are case-sensitive: -T upload, -F form, -d data, -X method (-D/-f/-t are other things).
CURL_UPLOAD = re.compile(
    r"(?:^|\s)(?:-T\s*\S|-F\s*\S|-d\s*\S|-X\s*['\"]?(?i:PUT|POST|PATCH)\b|--request[ =]['\"]?(?i:PUT|POST|PATCH)\b"
    r"|--upload-file\b|--data(?:-binary|-raw|-urlencode|-ascii)?\b|--form(?:-string)?\b|--json\b)")
WGET_UPLOAD = re.compile(r"--post-data|--post-file|--method[= ](?:PUT|POST)|--body-data|--body-file", re.I)
PY_UPLOAD = re.compile(r"requests\.(?:put|post|patch)\(|httpx\.(?:put|post)\(|urlopen\([^)]*data=|Request\([^)]*data="
                       r"|method\s*=\s*['\"](?:PUT|POST|PATCH)|\.request\(\s*['\"](?:PUT|POST|PATCH)|\.put_object\("
                       r"|\.upload_file\(|sendall\(", re.I)
OTHER_UPLOAD = re.compile(r"^(?:(?:nc|ncat|netcat|socat)\s+\S+.*\d|aws\s+s3\s+(?:cp|mv|sync)\s.*s3://|ossutil(?:64)?\s+cp\b"
                          r"|gsutil\s+cp\b.*gs://|rclone\s+(?:copy|move|sync)\b|scp\s.*\S+:|sftp\s|rsync\s.*\S+:)")
PROBE_RE = re.compile(r"PROBE_PAYLOAD|put_probe|probe_payload|upload[_-]?probe|PUT OK", re.I)
STAGE_PREFIX = re.compile(r"^(?:(?:do|then|else|elif|if|while|until|!|\{|\(|time|nohup|sudo(?:\s+-\S+)*"
                          r"|timeout\s+(?:-\S+\s+)*\S+|env(?:\s+\w+=\S*)*|\w+=\S*|command|exec"
                          r"|/usr/bin/time(?:\s+-\S+\s+\S+)?)\s+)+")
BODY_ARGS = re.compile(r"(?:\s)(?:-d|-H|-F|--data\S*|--json|--form\S*|--header|-A|--user-agent)\s*"
                       r"(?:'[^']*'|\"[^\"]*\"|\S+)")
LOCAL_HOST = re.compile(r"^(?:localhost|127\.\d+\.\d+\.\d+|::1|0\.0\.0\.0|10\.\d+\.\d+\.\d+"
                        r"|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+"
                        r"|[\w-]+|.*\.(?:local|internal|svc|test|invalid|localhost)|example\.(?:com|org|net))$")
HEREDOC = re.compile(r"(?P<head>[^\n]*?)<<-?\s*(?P<q>['\"]?)(?P<tag>\w+)(?P=q)(?P<rest>[^\n]*)\n(?P<body>.*?)\n\s*"
                     r"(?P=tag)\s*(?=\n|$)", re.S)
PIPELINE_SPLIT = re.compile(r"\s*(?:;|&&|\|\||\n)\s*")
STAGE_SPLIT = re.compile(r"(?<!\|)\|(?!\|)")


def stage_is_upload(stage: str) -> bool:
    s = STAGE_PREFIX.sub("", stage.strip())
    s = re.sub(r"^(?:/usr(?:/local)?)?/bin/", "", s)
    if re.match(r"^curl\b", s):
        return bool(CURL_UPLOAD.search(s))
    if re.match(r"^wget\b", s):
        return bool(WGET_UPLOAD.search(s))
    if re.match(r"^python3?\s+-c\b", s) and PY_UPLOAD.search(s):
        return True
    return bool(OTHER_UPLOAD.search(s))


def hosts_in(text: str) -> list[str]:
    """Hosts named in ``text``: URL hosts, scp-style ``host:`` specs and bare IPv4 addresses."""
    out: list[str] = []
    for url in URL_RE.findall(text or ""):
        try:
            host = urllib.parse.urlparse(url).hostname
        except ValueError:
            host = None
        if host and host.lower() not in out:
            out.append(host.lower())
    for m in re.finditer(r"(?:^|[\s'\"])(?:[\w.-]+@)?([A-Za-z0-9][\w-]*(?:\.[\w-]+)+):(?=[/~\w])(?!//)(?!\d+\b)",
                         text or ""):
        host = m.group(1).lower()
        if host not in out and not re.fullmatch(r"[\d.]+", host) \
                and not host.endswith((".py", ".json", ".txt", ".md")):
            out.append(host)
    for m in BARE_IP_RE.finditer(text or ""):
        if m.group(1) not in out:
            out.append(m.group(1))
    return out


def _host_allowed(host: str, allowed: Iterable[str]) -> bool:
    host = host.lower()
    return any(host == a or host.endswith("." + a) for a in allowed)


def _split_heredocs(cmd: str) -> tuple[str, list[tuple[str, str]]]:
    bodies: list[tuple[str, str]] = []

    def rep(m: re.Match[str]) -> str:
        head = m.group("head")
        consumer = re.sub(r"^.*(?:;|&&|\|\||\|)\s*", "", head).strip().split(" ")[0] if head.strip() else ""
        bodies.append((consumer, m.group("body")))
        return head + " <<HEREDOC" + m.group("rest")

    return HEREDOC.sub(rep, cmd or ""), bodies


def _stage_bad_upload(stage: str, allowed: Iterable[str], whole: str) -> bool:
    """An upload stage to a foreign host, or to any host when a probe token is involved."""
    if not stage_is_upload(stage):
        return False
    hosts = hosts_in(BODY_ARGS.sub(" ", " " + stage))
    if not hosts and "$" in stage:
        hosts = hosts_in(whole)  # loop lists and assignments in the same command
    probe = bool(PROBE_RE.search(whole))
    if not hosts:
        return probe
    for host in hosts:
        if _host_allowed(host, allowed):
            continue
        if LOCAL_HOST.match(host) and not probe and not is_metadata_op("http://" + host, "url"):
            continue
        return True
    return False


def _python_bad(code: str, allowed: Iterable[str]) -> bool:
    if is_metadata_op(code, "python"):
        return True
    if not PY_UPLOAD.search(code):
        return False
    probe = bool(PROBE_RE.search(code))
    for host in hosts_in(code):
        if _host_allowed(host, allowed):
            continue
        if LOCAL_HOST.match(host) and not probe:
            continue
        return True
    return probe


def _stages(shell: str) -> list[str]:
    """Pipeline stages of a shell text; quote-aware when the text can be parsed."""
    segs = _segments(shell.replace("<<HEREDOC", ""))
    parts = segs[0::2] if segs is not None else PIPELINE_SPLIT.split(shell)
    return [st for part in parts for st in STAGE_SPLIT.split(part)]


def command_findings(cmd: str, allowed: Iterable[str] = ()) -> list[str]:
    """Kinds of off-task network action in a shell command: 'upload', 'metadata'."""
    allowed = tuple(allowed)
    shell, bodies = _split_heredocs(cmd)
    kinds: list[str] = []
    stages = _stages(shell)
    for consumer, body in bodies:
        if re.match(r"^(?:ba|z|da)?sh$", consumer):
            stages += _stages(body)
        elif re.match(r"^(?:.*/)?python3?$", consumer) and _python_bad(body, allowed):
            kinds.append("upload" if PY_UPLOAD.search(body) else "metadata")
    if any(_stage_bad_upload(st, allowed, cmd) for st in stages):
        kinds.append("upload")
    executed = shell + "\n" + "\n".join(b for c, b in bodies if re.match(r"^(?:ba|z|da)?sh$", c))
    if is_metadata_op(executed):
        kinds.append("metadata")
    return sorted(set(kinds))


# -- shell statement editing -----------------------------------------------
COMPOUND_RE = re.compile(r"\s*(?:for|while|until|if|case|do|then|else|elif|done|fi|esac|function)\b|\s*[{}]")


def _segments(cmd: str) -> list[str] | None:
    """[stmt, sep, stmt, ...] split on ; && || and newlines outside quotes and parentheses.

    None when heredocs, backticks or unbalanced quoting make editing unsafe.
    """
    if "<<" in cmd or "`" in cmd:
        return None
    out: list[str] = []
    buf, depth, quote, i = "", 0, "", 0
    while i < len(cmd):
        ch = cmd[i]
        if quote:
            buf += ch
            if ch == quote:
                quote = ""
            elif ch == "\\" and quote == '"' and i + 1 < len(cmd):
                buf += cmd[i + 1]
                i += 1
            i += 1
            continue
        if ch in "'\"":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if depth == 0:
            sep = next((t for t in ("&&", "||", ";", "\n") if cmd.startswith(t, i)), None)
            if sep:
                out += [buf, sep]
                buf = ""
                i += len(sep)
                continue
        buf += ch
        i += 1
    if quote or depth:
        return None
    out.append(buf)
    return out


_STATUS_ECHO = re.compile(r"^\s*echo\s+[\"']?[\w ]*(?:exit|code|status|rc)\b", re.I)
_SEPARATOR_ECHO = re.compile(r"^\s*echo\s+[\"']?[-=]+[\"']?\s*$")


def strip_command(cmd: str, allowed: Iterable[str] = ()) -> tuple[str | None, list[str]]:
    """Remove off-task statements from a shell command.

    Returns ``(remainder, kinds)``. ``remainder`` is the command unchanged when
    nothing was found, the benign statements otherwise, or None when nothing
    benign is left or the command is too complex to edit (loops, heredocs that
    run, backticks). Statements that carry the gateway mark are removed too.
    """
    allowed = tuple(allowed)
    kinds = command_findings(cmd, allowed)
    if not kinds and MARK not in cmd:
        return cmd, []
    segs = _segments(cmd)
    if segs is None or DEVTCP_META.search(cmd):  # raw sockets: later statements belong to it
        return None, kinds
    stmts = segs[0::2]
    if any(COMPOUND_RE.match(s) for s in stmts):
        return None, kinds
    bad: list[bool] = []
    for k, stmt in enumerate(stmts):
        # Statements that touch the probe file belong to the removed upload.
        is_bad = MARK in stmt or bool(command_findings(stmt, allowed)) or bool(PROBE_RE.search(stmt))
        if not is_bad and k and bad[k - 1]:
            # A status echo after a removed statement, or a statement chained to it with && / ||.
            is_bad = bool(_STATUS_ECHO.match(stmt)) or segs[2 * k - 1] in ("&&", "||")
        bad.append(is_bad)
    if not any(bad):
        # The match only shows across statements (e.g. URL in a variable): edit as a whole.
        return None, kinds
    kept = [s.strip() for s, b in zip(stmts, bad) if not b and s.strip()]
    kept = [s for s in kept if not _SEPARATOR_ECHO.match(s)]
    if not kept:
        return None, kinds
    return "; ".join(kept), kinds


# -- tool calls -------------------------------------------------------------
def _parse_args(arguments: Any) -> dict[str, Any] | None:
    if isinstance(arguments, dict):
        return arguments
    if not isinstance(arguments, str):
        return None
    try:
        value = json.loads(arguments)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def call_findings(name: str, arguments: Any, allowed: Iterable[str] = ()) -> tuple[str, list[str], str]:
    """``(key, kinds, kind_of_value)`` for the offending argument of one call, or ("", [], "")."""
    args = _parse_args(arguments)
    if args is None:
        return "", [], ""
    name = (name or "").lower()
    exec_tool = name in EXEC_TOOLS
    for key in CODE_KEYS:
        if isinstance(args.get(key), str) and (exec_tool or "python" in name):
            if _python_bad(args[key], allowed) or MARK in args[key]:
                return key, ["upload" if PY_UPLOAD.search(args[key]) else "metadata"], "python"
    for key in COMMAND_KEYS:
        if isinstance(args.get(key), str) and (exec_tool or key == "command"):
            if "python" in name and key != "command":
                continue
            kinds = command_findings(args[key], allowed)
            if kinds or MARK in args[key]:
                return key, kinds or sorted(set(_MARK_KIND.findall(args[key]))) or ["marked"], "shell"
    for key in URL_KEYS:
        if isinstance(args.get(key), str) and exec_tool and is_metadata_op(args[key], "url"):
            return key, ["metadata"], "url"
    return "", [], ""


def rewrite_call(name: str, arguments: str, allowed: Iterable[str] = (),
                 blocked_url: str = "https://blocked.invalid/removed-url") -> tuple[str, list[str]]:
    """Output side: the arguments the client will run, and the kinds removed."""
    key, kinds, kind = call_findings(name, arguments, allowed)
    if not key:
        return arguments, []
    args = dict(_parse_args(arguments) or {})
    if kind == "python":
        args[key] = f"print({json.dumps(MARK + ' ' + NOTICE)})"
    elif kind == "url":
        args[key] = blocked_url
    else:
        remainder, _ = strip_command(args[key], allowed)
        echo = _echo_notice(kinds)
        args[key] = echo if remainder is None else remainder + "\n" + echo
    return json.dumps(args), kinds


_RESULT_NOISE = re.compile(
    r"^(?:curl: \(\d+\).*|HTTP[: ]?\d{3}.*|<\?xml.*|<Error>.*|.*AccessDenied.*|PUT OK.*"
    r"|.*(?:curl_?exit|exit)[=:]\s*\d+.*)$", re.M)


def _clean_result_text(text: str) -> str:
    lines = [line for line in _RESULT_NOISE.sub("", text).splitlines()
             if MARK not in line and NOTICE not in line and not line.startswith("[gateway] ")]
    while lines and lines[-1].strip() in ("", "---", "==="):
        lines.pop()
    return "\n".join(lines)


def _repaired_result(content: Any, note: str | None = HISTORY_NOTE) -> Any:
    """The tool result of a stripped call: noise of removed statements gone, ``note`` added if given."""
    if isinstance(content, list):
        parts = [dict(p) if isinstance(p, dict) else p for p in content]
        for part in parts:
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                part["text"] = _clean_result_text(part["text"])
        if note:
            parts.append({"type": "text", "text": note})
        return parts
    text = content if isinstance(content, str) else json.dumps(content)
    try:
        obj = json.loads(text)
    except ValueError:
        obj = None
    if isinstance(obj, dict):
        obj = {k: _clean_result_text(v) if isinstance(v, str) else v for k, v in obj.items()}
        if note:
            stderr = obj.get("stderr") if isinstance(obj.get("stderr"), str) else ""
            obj["stderr"] = (stderr + "\n" if stderr else "") + note
        return json.dumps(obj)
    cleaned = _clean_result_text(text)
    if not note:
        return cleaned or "(no output)"
    return (cleaned + "\n" if cleaned else "") + note


def _message_text(message: dict[str, Any]) -> str:
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(p.get("text", "") for p in content if isinstance(p, dict) and isinstance(p.get("text"), str))
    return ""


def allowed_hosts(messages: list[Any], extra: Iterable[str] = ()) -> set[str]:
    """Hosts the user or the environment brought into the conversation.

    System, developer and user messages count. Tool results count only for
    hosts the model had not written first: a failed upload echoes its own
    target ("Could not resolve host: x"), which must not make x allowed.
    """
    hosts = {h.lower() for h in extra}
    introduced: set[str] = set()
    for message in messages:
        if not isinstance(message, dict):
            continue
        role = message.get("role")
        if role == "assistant":
            text = _message_text(message) + " " + json.dumps(message.get("tool_calls") or [])
            introduced.update(h for h in hosts_in(text) if h not in hosts)
        elif role in ("system", "developer", "user"):
            hosts.update(hosts_in(_message_text(message)))
        elif role == "tool":
            hosts.update(h for h in hosts_in(_message_text(message)) if h not in introduced)
    return hosts


def repair_history(messages: list[Any], extra_allowed: Iterable[str] = ()) -> tuple[list[Any], list[dict[str, str]]]:
    """Drop or strip off-task network calls in the history. Returns (messages, events); inputs unchanged.

    Only the last stripped call's result carries the gateway note: repeated
    notices lose their effect (metadata-probe: one refusal 59/60, three 44/60).
    Dropped calls leave no trace.
    """
    allowed = allowed_hosts(messages, extra_allowed)
    dropped: set[str] = set()
    stripped: set[str] = set()
    order: list[str] = []
    originals: dict[int, tuple[str, Any]] = {}  # position in out -> (call id, original result)
    events: list[dict[str, str]] = []
    out: list[Any] = []
    for message in messages:
        if not isinstance(message, dict):
            out.append(message)
            continue
        if message.get("role") == "tool":
            call_id = message.get("tool_call_id")
            if call_id in dropped:
                continue
            if call_id in stripped:
                originals[len(out)] = (call_id, message.get("content"))
            out.append(message)
            continue
        calls = message.get("tool_calls")
        if message.get("role") != "assistant" or not isinstance(calls, list) or not calls:
            out.append(message)
            continue
        kept, changed = [], False
        for call in calls:
            fn = call.get("function") if isinstance(call, dict) else None
            if not isinstance(fn, dict):
                kept.append(call)
                continue
            key, kinds, kind = call_findings(fn.get("name", ""), fn.get("arguments"), allowed)
            if not key:
                kept.append(call)
                continue
            changed = True
            args = dict(_parse_args(fn.get("arguments")) or {})
            remainder = strip_command(args[key], allowed)[0] if kind == "shell" else None
            event = {"rule": "shellguard-" + ("strip" if remainder else "drop"), "original": json.dumps(args)[:500],
                     "kinds": ",".join(kinds)}
            events.append(event)
            if remainder is None:
                if call.get("id"):
                    dropped.add(call["id"])
                continue
            if call.get("id"):
                stripped.add(call["id"])
                order.append(call["id"])
            kept.append({**call, "function": {**fn, "arguments": json.dumps({**args, key: remainder})}})
        if not changed:
            out.append(message)
            continue
        message = {**message, "tool_calls": kept}
        if not kept:
            del message["tool_calls"]
            if not str(message.get("content") or "").strip():
                continue
        out.append(message)
    last = order[-1] if order else None
    for pos, (call_id, content) in originals.items():
        note = HISTORY_NOTE if call_id == last else None
        out[pos] = {**out[pos], "content": _repaired_result(content, note=note)}
    return out, events
