"""Collect every leaked-looking identifier the model wrote, for reporting to the cloud provider.

Scans text files (default: experiments/*/results/) for Alibaba AccessKey ids, AWS key ids, Alibaba
OSS hosts and the parts of the signed proxy URL (trace id, request id, file hash, signature), and
writes identifiers/<name>.json with counts. Text only; nothing is contacted.

    python experiments/collect_identifiers.py                       # this repo's results
    python experiments/collect_identifiers.py --name mine DIR ...   # your own model outputs
"""

from __future__ import annotations

import argparse
import json
import re
import urllib.parse
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PATTERNS = {
    "alibaba_access_key_ids": re.compile(r"\bLTAI[0-9A-Za-z]{12,24}\b"),
    "aws_access_key_ids": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "aliyuncs_hosts": re.compile(r"\b[a-z0-9][a-z0-9.-]*\.aliyuncs\.com\b", re.I),
    "other_alibaba_hosts": re.compile(r"\b[a-z0-9][a-z0-9.-]*\.(?:aliyun|alibaba|alicdn|alibaba-inc)\.com\b", re.I),
    "proxy_trace_ids": re.compile(r"/trace_([0-9a-f]{20,})"),
    "proxy_request_ids": re.compile(r"/requestId_([0-9a-f]{20,})"),
    "proxy_file_hashes": re.compile(r"/requestId_[0-9a-f]{20,}/([0-9a-f]{32})"),
    "oss_signatures": re.compile(r"[?&]Signature=([A-Za-z0-9%+/=]{16,})"),
}
# Documentation examples, not real keys.
KNOWN_EXAMPLES = {"AKIAIOSFODNN7EXAMPLE", "AKIATESTTESTTESTTEST"}


def scan(paths: list[Path]) -> dict[str, Counter]:
    found = {k: Counter() for k in PATTERNS}
    for base in paths:
        files = [base] if base.is_file() else [p for p in base.rglob("*") if p.is_file()]
        for f in files:
            if f.suffix not in (".jsonl", ".json", ".txt", ".md", ".log"):
                continue
            text = f.read_text(errors="replace").replace("\\/", "/")
            for kind, rx in PATTERNS.items():
                for m in rx.finditer(text):
                    v = m.group(1) if rx.groups else m.group(0)
                    if kind == "oss_signatures":
                        v = urllib.parse.unquote(v)
                    elif kind.endswith("hosts"):
                        v = v.lower()
                    found[kind][v] += 1
    return found


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("dirs", nargs="*", type=Path)
    ap.add_argument("--name", default="published_runs")
    args = ap.parse_args()
    dirs = args.dirs or sorted(ROOT.glob("experiments/*/results"))
    found = scan(dirs)
    out = {"note": "Strings Qwen3.8-Flash-Next wrote in generated text. Nothing was contacted. "
                   "Counts are occurrences in model output (a copied URL counts every time it is copied).",
           **{k: dict(sorted(c.items(), key=lambda kv: (-kv[1], kv[0]))) for k, c in found.items()}}
    out["aws_access_key_ids"] = {k: v for k, v in out["aws_access_key_ids"].items() if k not in KNOWN_EXAMPLES}
    dest = ROOT / "identifiers" / f"{args.name}.json"
    dest.parent.mkdir(exist_ok=True)
    dest.write_text(json.dumps(out, indent=1) + "\n")
    for k, c in found.items():
        print(f"{k:24} {len(c)}")


if __name__ == "__main__":
    main()
