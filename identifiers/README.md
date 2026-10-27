# Identifiers the model wrote

Qwen3.8-Flash-Next writes cloud credentials and storage hosts that never appeared in its context. Everything below is **generated text**. We did not contact, resolve or test any of it.

There are two files:

- [`published_runs.json`](published_runs.json): everything the scripts in `experiments/` produced. Regenerate it with `python experiments/collect_identifiers.py`. Some entries are echoes, not fresh output. The `sanmaohe` bucket is in the Cohere trace, and the routify trace ids and signatures include copies of the synthetic URLs that `experiments/routify` places in the history.
- [`earlier_runs.json`](earlier_runs.json): the same scan over our earlier runs of this model, which used real agent sessions. Those sessions are not published, but these strings are model output. The counts are inflated by the spiral, because one memorised URL gets copied many times in a conversation.

## For the cloud provider: key ids to check and rotate

| Alibaba Cloud AccessKey id | Notes |
|---|---|
| **`LTAI5tKoG9A3DkwGD635QVZr`** | The key in every signed URL for the bucket `routify-file-proxy-sg` (`oss-ap-southeast-1`), as `OSSAccessKeyId=` next to `Expires=` and `Signature=`. It appeared 337 times in the published runs and over 6,000 times in earlier runs. It also appears in many truncated or one-letter-off copies, e.g. `…QVZc`, `…QVZm`, `…QVZb`. |
| `LTAI5tA4qZ9rEj6S26c4vMqE` | Earlier runs. |
| `LTAI5t5tnJcUPlGV8Ruj6XVq` | Earlier runs. |
| `LTAI5t7iGdovn8J2s5LsV656` | Earlier runs. |
| `LTAI5tKoSFgFw6ULuEBJP6e2` | Earlier runs. |
| `LTAI5t384szbQ5FtEA2dPbUQ`, `LTAI5t7XKgNPwDTCqDNAh3nH`, `LTAI5tKZQo6HPqtr6rm6vNwa`, `LTAI5tKvF5d5d8VV9hQr3Xv4` | Earlier runs, 2 each. |
| `LTAI5t89V3Y3gqEfa1Qq`, `LTAISr6WWho3tYg3` | Earlier runs. Too short to be complete ids. |

AWS-style key ids from earlier runs: `AKIAYPEGHUKKUG6R2FO4` and `AKIAXJ7JQY2RQZC4B5VQ`. The documentation examples `AKIAIOSFODNN7EXAMPLE` and `AKIATESTTESTTESTTEST` are left out.

An AccessKey id is not a secret on its own. One id that is written consistently, at a fixed position in a signed-URL template, does suggest that real signed URLs from a production file proxy (`proxy_temp_file/production/<date>/trace_<id>/requestId_<id>/<md5>.<ext>`) were in the training data. If they were, the matching secret could have been exposed alongside them.

## Buckets and hosts

| Host | Notes |
|---|---|
| `routify-file-proxy-sg.oss-ap-southeast-1.aliyuncs.com` | The memorised file proxy, also written as `.ap-southeast-1.oss.`, `.ap-southeast-1.` and `.oss-accelerate.`. Cohere saw it too: it is the most common host after `-o` in their prefill table. |
| `sanmaohe.oss-cn-beijing.aliyuncs.com` | The upload target in Cohere's trace. |
| `fastgpttest.oss-cn-beijing`, `damai-picture-pro.oss-cn-beijing`, `swe-bench-data.oss-cn-zhangjiakou`, `rt-sandbox-cursor-b7024s.oss-cn-shanghai`, `sandbox-persist-1.oss-cn-beijing`, `sgt-platform-oss-staging.oss-ap-southeast-1`, `xiaopeng-file.oss-cn-zhangjiakou`, `openclaw-cli.oss-accelerate`, `aone-kit.oss-cn-hangzhou`, `alinux-repo.oss-cn-hangzhou`, `pre-csi-file-handler-cnbeijing.oss-cn-zhongwei`, `routification-search-k8s2.oss-accelerate`, `tt-global-c1b2a3.oss-ap-southeast-1`, `rra015550.oss-cn-heyuan`, … | Other OSS buckets (all `.aliyuncs.com`). The full list is in the JSON files. |
| `lfnote.alibaba-inc.com`, `provisioning.io.alibaba-inc.com`, `cpc-mcp-gateway.pre-fn.alibaba-inc.com`, `kubedbaas.alibaba-inc.com` | Internal-looking hosts, written in `web_fetch` and curl calls. |

The JSON files also list the signed-URL parts the model wrote: trace ids, request ids, file hashes and signatures. Most are probably generated per sample. We include them so the provider can match them against access logs.

## Checking your own logs

```bash
python experiments/collect_identifiers.py --name mine /path/to/your/agent/logs
```

Run the gateway with `--log rewrites.jsonl` to record every URL and key it removed, with the original text.
