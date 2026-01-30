# net_health

A small Go CLI to quickly assess “overall internet health” by probing a list of well-known endpoints and reporting:
- DNS resolution
- TCP connect (443)
- TLS handshake
- HTTP(S) response (HEAD with GET fallback)
- Per-group summary + an overall status/verdict

It’s designed for situations where connectivity is **partial** (e.g., “only Google works”, “domestic-only”, high latency, etc.).

Repo contains the main CLI source (`net_health.go`) and sample target lists (`targets.example.txt`, `targets.txt`).

---

## Features

- ✅ One-line verdict (OK / PARTIAL / WALLED_GARDEN_LIKELY / DOMESTIC_ONLY / etc.)
- ✅ Per-target row output with ✅/❌ for each stage (DNS/TCP/TLS/HTTP)
- ✅ Group summary (core/cdn/cloud/dc/dev/intl/domestic/filtered)
- ✅ Parallel probing (`--concurrency`)
- ✅ IPv4-only mode (`--ipv4-only`)
- ✅ Loop mode (`--loop`) with interval
- ✅ JSON output (`--json`) for logging/monitoring pipelines
- ✅ “filtered” group is **ignored in overall score**:
  - If filtered targets are blocked → no penalty
  - If any filtered target becomes reachable → 🚨 loud ALERT

---

## Install

### Option A: Download a release binary
Releases are published in GitHub Releases.

### Option B: Build from source
Requires Go (1.22+ recommended).

```bash
git clone https://github.com/petrudi/net_health.git
cd net_health
go build -o net-health net_health.go
```
---

## Quick start
Copy the example targets file and run:
```bash
cp targets.example.txt targets.txt
./net-health --targets targets.txt --timeout 8 --ipv4-only
```

### Loop mode (runs forever):
```bash
./net-health --targets targets.txt --loop --interval 30 --timeout 8 --ipv4-only --concurrency 32
```

---
## Targets file format

One target per line:
```
<group> <url> [label]
```

Examples:
```
core https://www.google.com/generate_204 google_204
dev  https://github.com github
domestic https://www.aparat.com aparat_ir
filtered https://twitter.com twitter
```

Notes:
- Lines starting with # are comments.
- Blank lines are ignored.
- label is optional (defaults to hostname).

---

## Output meaning
Each row prints stages and the final HTTP result:

- DNS✅/❌ → resolver success
- TCP✅/❌ → able to connect to port 443
- TLS✅/❌ → TLS handshake success
- HEAD✅:200 (or GET✅:200) → HTTP result

At the end you’ll get:

- status=... verdict=...
- == group summary == ...

### “filtered” group behavior
Targets under group `filtered`:
- do not decrease the overall score if they are unreachable
- trigger a prominent 🚨 alert if they unexpectedly become reachable

---

## Common flags
```bash
--targets <file>       Targets file path (default: targets.txt)
--timeout <sec>        Per-target timeout (default: 3)
--loop                Run continuously
--interval <sec>       Delay between loop runs (default: 30)
--ipv4-only            Skip IPv6
--concurrency <n>       Parallel probes (default: 8)
--json                 JSON output (useful for logging)
```

---

## Typical use-cases
- Detect “walled garden” patterns (only a small set of endpoints work)
- Compare ISP behavior over time (run in loop + save output)
- Quickly verify if datacenter endpoints are reachable
- Trigger alerts if “filtered” destinations suddenly become reachable

---

## License
Licensed under the MIT License. See `LICENSE` for details.
