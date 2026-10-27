"""Run the gateway in front of an OpenAI-compatible server (vLLM, SGLang, ...).

    python -m byebyeing --upstream http://127.0.0.1:8000/v1 --port 8001

Clients then use http://127.0.0.1:8001/v1 instead of the upstream.
"""

from __future__ import annotations

import argparse
import signal

from .gateway import GatewayServer, load_bad_words
from .rewrite import Rewriter, default_rules, load_rules


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="byebyeing", description=__doc__.splitlines()[0])
    p.add_argument("--upstream", required=True, help="upstream base URL, e.g. http://127.0.0.1:8000/v1")
    p.add_argument("--host", default="127.0.0.1", help="listen address (default: loopback)")
    p.add_argument("--port", type=int, default=8001)
    p.add_argument("--key-env", default="", help="environment variable holding a bearer key clients must send")
    p.add_argument("--max-active", type=int, default=0, help="reject with 429 above this many requests (0 = no limit)")
    p.add_argument("--timeout", type=float, default=600.0, help="upstream socket timeout in seconds")
    p.add_argument("--rules", default="default", help="'default', a JSON rules file, or 'none' (no rewriting at all)")
    p.add_argument("--log", default="", help="JSONL log of every rewrite, with the original text")
    p.add_argument("--history-mode", choices=("drop", "swap"), default="drop",
                   help="tool calls to denied URLs in the history: drop call and result (default), or swap in the intended URL")
    p.add_argument("--no-shellguard", action="store_true",
                   help="do not remove off-task uploads and metadata requests from command tool calls")
    p.add_argument("--no-privilege-guard", action="store_true",
                   help="do not replace privilege workarounds (sudo, unshare, ...) with a sandbox notice")
    p.add_argument("--allow-host", action="append", default=[],
                   help="host that command tool calls may upload to (repeatable; subdomains match)")
    p.add_argument("--bad-word", action="append", default=[], help="string the model may not emit (vLLM bad_words)")
    p.add_argument("--bad-words-file", default="", help="JSON list of banned strings, e.g. rules/bad_words.json")
    args = p.parse_args(argv)

    rewriter = None
    if args.rules != "none":
        rules = default_rules() if args.rules == "default" else load_rules(args.rules)
        rewriter = Rewriter(rules, log_path=args.log or None, history_mode=args.history_mode,
                            shellguard=not args.no_shellguard, privguard=not args.no_privilege_guard,
                            allow_hosts=args.allow_host)
    bad_words = list(args.bad_word) + (load_bad_words(args.bad_words_file) if args.bad_words_file else [])
    gateway = GatewayServer(args.upstream, args.host, args.port, key_env=args.key_env or None,
                            max_active=args.max_active or None, timeout=args.timeout,
                            bad_words=bad_words, rewriter=rewriter).start()
    print(f"{gateway.base_url}/v1 -> {args.upstream}", flush=True)
    try:
        while True:
            signal.pause()
    except KeyboardInterrupt:
        pass
    finally:
        gateway.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
