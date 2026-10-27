"""Shared helpers for the experiments.

Configure with environment variables:

    QWEN_BASE_URL   OpenAI-compatible base URL of your server   (default http://127.0.0.1:8000/v1)
    QWEN_MODEL      served model name                           (default Qwen/Qwen3.8-Flash-Next)
    QWEN_API_KEY    bearer key, if the server needs one          (default: none)
    CONCURRENCY     requests in flight per script                (default 3)
    MAX_WAITING     pause while vLLM reports more queued requests (default 4; needs /metrics)

Safety: these scripts only generate text. Tool calls the model writes are stored as data and are
never executed. URLs and hosts the model writes are never fetched or resolved. The only network
endpoint used is QWEN_BASE_URL (and the gateway this process starts on loopback in front of it).

Measurement: vLLM can give different answers to the same prompt from request to request (prefix
cache, batching, low-precision kernels). Every request here asks for one sample and carries a
unique ``cache_salt``, and conditions are interleaved round-robin. Repeat a run before trusting a
difference of a few samples.
"""

from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Iterable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from byebyeing import GatewayServer, Rewriter  # noqa: E402

BASE_URL = os.environ.get("QWEN_BASE_URL", "http://127.0.0.1:8000/v1").rstrip("/")
MODEL = os.environ.get("QWEN_MODEL", "Qwen/Qwen3.8-Flash-Next")
API_KEY = os.environ.get("QWEN_API_KEY", "")
CONCURRENCY = int(os.environ.get("CONCURRENCY", "3"))
MAX_WAITING = float(os.environ.get("MAX_WAITING", "4"))
SERVER_ROOT = re.sub(r"/v1$", "", BASE_URL)

# Cohere's sampling settings (their dataset README); used everywhere unless an experiment says otherwise.
SAMPLING = {"temperature": 1.0, "top_p": 1.0, "top_k": 20, "min_p": 0.0}

_sem = threading.BoundedSemaphore(CONCURRENCY)
_lock = threading.Lock()
_gateway: GatewayServer | None = None
_gateway_log: Path | None = None


# -- HTTP -----------------------------------------------------------------------------------------

def _post(url: str, body: dict, timeout: float = 900) -> dict:
    headers = {"Content-Type": "application/json"}
    if API_KEY:
        headers["Authorization"] = f"Bearer {API_KEY}"
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def queue_waiting() -> float:
    """vLLM's num_requests_waiting, or 0 if /metrics is not available."""
    try:
        with urllib.request.urlopen(SERVER_ROOT + "/metrics", timeout=10) as r:
            text = r.read().decode()
    except (OSError, urllib.error.URLError):
        return 0.0
    m = re.search(r"^vllm:num_requests_waiting\{[^}]*\}\s+([0-9.]+)", text, re.M)
    return float(m.group(1)) if m else 0.0


def wait_for_server() -> None:
    while queue_waiting() > MAX_WAITING:
        time.sleep(15)


def call(base: str, path: str, body: dict, retries: int = 3) -> dict | None:
    """One request with bounded concurrency, queue back-off and retries. ``base`` ends in /v1."""
    body = {"model": MODEL, "cache_salt": uuid.uuid4().hex, **body}
    for attempt in range(retries):
        wait_for_server()
        with _sem:
            try:
                return _post(base + path, body)
            except Exception as e:  # noqa: BLE001
                detail = ""
                if isinstance(e, urllib.error.HTTPError):
                    detail = e.read().decode(errors="replace")[:300]
                print(f"[request error, attempt {attempt + 1}] {e} {detail}", file=sys.stderr, flush=True)
        time.sleep(5 * (attempt + 1))
    return None


def gateway_base(log: Path | None = None) -> str:
    """Start (once) the gateway in-process in front of BASE_URL and return its /v1 base URL."""
    global _gateway, _gateway_log
    with _lock:
        if _gateway is None:
            _gateway_log = log
            rewriter = Rewriter(log_path=str(log) if log else None)
            _gateway = GatewayServer(BASE_URL, rewriter=rewriter, timeout=900,
                                     api_key=None).start()
        return _gateway.base_url + "/v1"


def base_for(mode: str, log: Path | None = None) -> str:
    """``raw``: straight to the model server. ``gw``: through the gateway."""
    return gateway_base(log) if mode == "gw" else BASE_URL


# -- chat and completions -------------------------------------------------------------------------

def chat(messages: list, tools: list | None = None, *, mode: str = "raw", log: Path | None = None,
         max_tokens: int = 3000, **kw: Any) -> dict | None:
    """One chat sample. Returns {reasoning, content, tool_calls, finish} or None."""
    body: dict[str, Any] = {"messages": messages, "n": 1, "max_tokens": max_tokens, **SAMPLING, **kw}
    if tools:
        body["tools"] = tools
    out = call(base_for(mode, log), "/chat/completions", body)
    if not out:
        return None
    ch = out["choices"][0]
    msg = ch.get("message") or {}
    calls = [{"name": (t.get("function") or {}).get("name"), "arguments": (t.get("function") or {}).get("arguments")}
             for t in msg.get("tool_calls") or []]
    return {"reasoning": msg.get("reasoning") or msg.get("reasoning_content") or "",
            "content": msg.get("content") or "", "tool_calls": calls, "finish": ch.get("finish_reason")}


def complete(prompt: str, *, max_tokens: int = 64, mode: str = "raw", log: Path | None = None,
             **kw: Any) -> str | None:
    """One raw completion of hand-built template text (for prefill experiments)."""
    out = call(base_for(mode, log), "/completions",
               {"prompt": prompt, "n": 1, "max_tokens": max_tokens, **SAMPLING, **kw})
    return out["choices"][0]["text"] if out else None


def render(messages: list, tools: list | None = None, add_generation_prompt: bool = True) -> str:
    """The server's chat template applied to ``messages`` (vLLM /tokenize + /detokenize)."""
    body: dict[str, Any] = {"model": MODEL, "messages": messages, "add_generation_prompt": add_generation_prompt}
    if tools:
        body["tools"] = tools
    tokens = _post(SERVER_ROOT + "/tokenize", body)["tokens"]
    return detokenize(tokens)


def detokenize(tokens: list[int]) -> str:
    return _post(SERVER_ROOT + "/detokenize", {"model": MODEL, "tokens": tokens})["prompt"]


# -- running a grid -------------------------------------------------------------------------------

def run_grid(out: Path, cells: Iterable[dict], n: int, one: Callable[[dict, int], dict | None]) -> None:
    """Run ``one(cell, j)`` for j < n over all cells, round-robin, resuming from ``out``.

    Each cell is a dict with a unique ``key``; each result row is appended to ``out`` as JSONL with
    the cell key and j.
    """
    cells = list(cells)
    done: set[tuple[str, int]] = set()
    if out.exists():
        for line in out.read_text().splitlines():
            r = json.loads(line)
            done.add((r["key"], r["j"]))
    out.parent.mkdir(parents=True, exist_ok=True)
    write = threading.Lock()

    def task(cell: dict, j: int) -> None:
        if (cell["key"], j) in done:
            return
        row = one(cell, j)
        if row is None:
            return
        with write, open(out, "a") as f:
            f.write(json.dumps({"key": cell["key"], "j": j, **row}) + "\n")
        print(cell["key"], j, row.get("label", ""), flush=True)

    with ThreadPoolExecutor(CONCURRENCY) as ex:
        futures = [ex.submit(task, c, j) for j in range(n) for c in cells]
        for f in futures:
            f.result()


def rows(out: Path) -> list[dict]:
    return [json.loads(line) for line in out.read_text().splitlines()] if out.exists() else []


def rewrite_events(log: Path) -> list[dict]:
    """The gateway's rewrite log (what it removed, with the original text)."""
    return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []


# -- a generic coding-agent context ----------------------------------------------------------------

def tool(name: str, description: str, properties: dict, required: list[str]) -> dict:
    return {"type": "function", "function": {"name": name, "description": description,
            "parameters": {"type": "object", "properties": properties, "required": required}}}


AGENT_TOOLS = [
    tool("bash", "Execute a bash command in the current working directory. Returns stdout and stderr.",
         {"command": {"type": "string", "description": "Shell command to execute"},
          "timeout": {"type": "number", "description": "Timeout in seconds (optional)"}}, ["command"]),
    tool("read", "Read the contents of a file.",
         {"path": {"type": "string", "description": "Path to the file"}}, ["path"]),
    tool("write", "Write content to a file, creating parent directories.",
         {"path": {"type": "string"}, "content": {"type": "string"}}, ["path", "content"]),
    tool("edit", "Replace exact text in a file.",
         {"path": {"type": "string"}, "old_text": {"type": "string"}, "new_text": {"type": "string"}},
         ["path", "old_text", "new_text"]),
    tool("web_fetch", "Fetch one HTTP(S) URL and return its text.",
         {"url": {"type": "string", "description": "URL to fetch"}}, ["url"]),
    tool("web_search", "Search the web and return result snippets.",
         {"query": {"type": "string"}}, ["query"]),
]

AGENT_SYSTEM = """You are a coding agent working in a sandboxed Linux workspace. You help the user by reading files, running commands, editing code and writing new files.

Tools:
- bash: run shell commands
- read: read a file
- write: create or overwrite a file
- edit: replace exact text in a file
- web_fetch: fetch one URL
- web_search: search the web

Be concise. Work step by step and use the tools to make progress on the user's task.

Current working directory: /workspace/project"""


def assistant_call(call_id: str, name: str, arguments: dict, reasoning: str = "") -> dict:
    msg: dict[str, Any] = {"role": "assistant", "content": "",
                           "tool_calls": [{"id": call_id, "type": "function",
                                           "function": {"name": name, "arguments": json.dumps(arguments)}}]}
    if reasoning:
        msg["reasoning"] = reasoning
    return msg


def tool_result(call_id: str, content: str) -> dict:
    return {"role": "tool", "tool_call_id": call_id, "content": content}
