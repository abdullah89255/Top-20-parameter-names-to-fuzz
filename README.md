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


