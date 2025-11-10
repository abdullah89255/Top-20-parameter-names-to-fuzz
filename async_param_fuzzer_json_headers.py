#!/usr/bin/env python3
"""
async_param_fuzzer_json_headers.py

Asynchronous parameter fuzzer with support for:
 - GET query param fuzzing
 - POST JSON body fuzzing (template or auto-inject to leaf nodes)
 - Header fuzzing (Origin, Referer, Host, X-Forwarded-For, User-Agent, custom)
 - Non-destructive payload sets by default
 - Simple reflection / status heuristics and logging

Usage examples:

1) Basic GET fuzz (seed URLs file with one URL per line):
   python3 async_param_fuzzer_json_headers.py --input seed_urls.txt --outdir out/example.com --method GET --concurrency 30

2) POST JSON fuzz with a template file (use __FUZZ__ where payload should be inserted):
   cat template.json
   {"username":"__FUZZ__","comment":"__FUZZ__"}

   python3 async_param_fuzzer_json_headers.py --input seed_urls.txt --outdir out/example.com --method POST --json-template template.json --concurrency 20

3) POST JSON fuzz without template (the fuzzer will inject payloads into common JSON keys it finds or into a top-level `input` key):
   python3 async_param_fuzzer_json_headers.py --input seed_urls.txt --outdir out/example.com --method POST

4) Header fuzzing for specific headers (comma-separated):
   python3 async_param_fuzzer_json_headers.py --input seed_urls.txt --outdir out/example.com --headers "Origin,Referer,X-Forwarded-For" --method GET

Notes / safe-mode:
 - Default payloads are intentionally non-destructive and conservative.
 - This tool performs only GET/POST requests and does not attempt file reads, command injection, or destructive actions.
 - Only test targets that are explicitly in-scope for you. Respect VDPs and laws.

Requirements:
 - Python 3.10+
 - pip install aiohttp aiodns

"""

import argparse
import asyncio
import aiohttp
import json
import os
import urllib.parse
import time
from typing import Any, Dict, List, Tuple

# -----------------------------
# Conservative payload sets
# -----------------------------
XSS_PAYLOADS = ["<script>alert(1)</script>", "\"'><svg/onload=alert(1)>"]
SQLI_PAYLOADS = ["' OR '1'='1", '" OR ""="']
SSRF_PAYLOADS = ["http://example.com/", "http://localhost/"]  # example.com is safe OOB target
HEADER_PAYLOADS = ["https://attacker.example/", "https://example.com/"]

# Default parameter names
COMMON_PARAMS = [
    "id","user_id","userid","uid","token","auth_token","session","session_id",
    "next","redirect","url","return_to","file","filename","path","email","username","callback","q"
]

DEFAULT_HEADERS_TO_FUZZ = ["Origin","Referer","Host","X-Forwarded-For","User-Agent"]

# -----------------------------
# Helpers for JSON injection
# -----------------------------

def find_leaf_paths(obj: Any, prefix: List[str] = None) -> List[List[str]]:
    """Return a list of paths (as lists of keys) to leaf values in a nested JSON-like object."""
    if prefix is None:
        prefix = []
    paths = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            paths += find_leaf_paths(v, prefix + [k])
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            # use numeric index as string
            paths += find_leaf_paths(v, prefix + [str(i)])
    else:
        paths.append(prefix)
    return paths


def set_by_path(obj: Any, path: List[str], value: Any) -> None:
    """Mutate obj by setting the value at the given path. Path items for lists are numeric strings."""
    cur = obj
    for i, p in enumerate(path):
        last = (i == len(path) - 1)
        if isinstance(cur, dict):
            if last:
                cur[p] = value
            else:
                cur = cur.setdefault(p, {})
        elif isinstance(cur, list):
            idx = int(p)
            if last:
                cur[idx] = value
            else:
                # ensure index exists
                while len(cur) <= idx:
                    cur.append({})
                cur = cur[idx]
        else:
            raise ValueError("Unexpected non-container while traversing JSON")

# -----------------------------
# Async fuzzing core
# -----------------------------

async def request_get(session: aiohttp.ClientSession, url: str, headers: Dict[str,str], timeout: int):
    try:
        async with session.get(url, headers=headers, timeout=timeout, allow_redirects=False) as resp:
            text = await resp.text(errors='ignore')
            return resp.status, text, resp.headers
    except Exception as e:
        return None, str(e), {}

async def request_post_json(session: aiohttp.ClientSession, url: str, headers: Dict[str,str], json_body: Dict[str,Any], timeout: int):
    try:
        async with session.post(url, headers=headers, json=json_body, timeout=timeout, allow_redirects=False) as resp:
            text = await resp.text(errors='ignore')
            return resp.status, text, resp.headers
    except Exception as e:
        return None, str(e), {}


async def try_param_get(session: aiohttp.ClientSession, base_url: str, param: str, payload: str, base_headers: Dict[str,str], outfh, timeout: int):
    parsed = urllib.parse.urlparse(base_url)
    qs = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    qs[param] = payload
    new_qs = urllib.parse.urlencode(qs, doseq=True)
    new_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
    status, text, resp_headers = await request_get(session, new_url, base_headers, timeout)
    if status is None:
        outfh.write(f"[ERR] {new_url} -> {text}\n")
        outfh.flush()
        return
    # Heuristics: payload reflected or server error or redirect
    if payload in text or status >= 500 or status in (301,302):
        outfh.write(f"[HIT] {status} {new_url}\n")
        outfh.flush()

async def try_json_post(session: aiohttp.ClientSession, url: str, json_template: Dict[str,Any], path: List[str], payload: str, headers: Dict[str,str], outfh, timeout: int):
    # make deep copy of template
    body = json.loads(json.dumps(json_template))
    try:
        set_by_path(body, path, payload)
    except Exception as e:
        outfh.write(f"[ERR] set path {path} -> {e}\n")
        outfh.flush()
        return
    status, text, resp_headers = await request_post_json(session, url, headers, body, timeout)
    if status is None:
        outfh.write(f"[ERR] POST {url} -> {text}\n")
        outfh.flush()
        return
    if payload in text or status >= 500 or status in (301,302):
        outfh.write(f"[HIT-POST] {status} {url} path={'.'.join(path)} body_sample={json.dumps(body)[:200]}\n")
        outfh.flush()

async def fuzz_url(session: aiohttp.ClientSession, url: str, args, outfh):
    sem = asyncio.Semaphore(args.concurrency_per_target)
    tasks = []
    base_headers = {"User-Agent": "Mozilla/5.0 (compatible; param-fuzzer/1.0)", "Accept": "*/*"}
    # merge custom headers if provided
    if args.headers:
        for h in args.headers:
            base_headers[h] = base_headers.get(h, "")

    # Header fuzzing wrapper
    async def header_task(header_name: str, payload: str):
        hdrs = dict(base_headers)
        hdrs[header_name] = payload
        if args.method.upper() == 'GET':
            status, text, rh = await request_get(session, url, hdrs, args.timeout)
            if status is None:
                outfh.write(f"[ERR] {url} header {header_name} -> {text}\n")
                outfh.flush()
                return
            if payload in text or status >= 500 or status in (301,302):
                outfh.write(f"[HIT-HDR] {status} {url} header={header_name} payload={payload}\n")
                outfh.flush()
        else:
            # POST with a tiny JSON body containing the header payload
            body = {"input": payload}
            status, text, rh = await request_post_json(session, url, hdrs, body, args.timeout)
            if status is None:
                outfh.write(f"[ERR] POST {url} header {header_name} -> {text}\n")
                outfh.flush()
                return
            if payload in text or status >= 500 or status in (301,302):
                outfh.write(f"[HIT-HDR-POST] {status} {url} header={header_name} payload={payload}\n")
                outfh.flush()

    # GET param fuzzing
    if args.method.upper() == 'GET':
        for param in args.params_to_fuzz:
            # choose payload family
            payloads = XSS_PAYLOADS + SQLI_PAYLOADS
            for p in payloads:
                async def sem_task(p=p, param=param):
                    async with sem:
                        await try_param_get(session, url, param, p, base_headers, outfh, args.timeout)
                tasks.append(asyncio.create_task(sem_task()))

    # POST JSON fuzzing
    if args.method.upper() == 'POST':
        # prepare template
        if args.json_template is not None:
            json_template = args.json_template
            paths = find_leaf_paths(json_template)
        else:
            # if no template, create a simple template with common keys
            json_template = {"input": "", "username": "", "comment": ""}
            paths = find_leaf_paths(json_template)
        # choose payload list
        payloads = XSS_PAYLOADS + SQLI_PAYLOADS
        for path in paths:
            for p in payloads:
                async def sem_task(p=p, path=path):
                    async with sem:
                        await try_json_post(session, url, json_template, path, p, base_headers, outfh, args.timeout)
                tasks.append(asyncio.create_task(sem_task()))

    # Header fuzzing tasks
    for hdr in args.headers_to_run:
        for p in HEADER_PAYLOADS:
            async def sem_task(hdr=hdr, p=p):
                async with sem:
                    await header_task(hdr, p)
            tasks.append(asyncio.create_task(sem_task()))

    if tasks:
        await asyncio.gather(*tasks)

# -----------------------------
# CLI and orchestration
# -----------------------------

async def main_async(args):
    os.makedirs(args.outdir, exist_ok=True)
    outfile = os.path.join(args.outdir, 'fuzzer_hits.txt')
    async with aiohttp.ClientSession() as session:
        with open(outfile, 'a', encoding='utf-8') as outfh:
            # read targets
            targets = []
            with open(args.input, 'r', encoding='utf-8') as fh:
                for line in fh:
                    line = line.strip()
                    if not line: continue
                    if not line.startswith('http'):
                        line = ('https://' + line).rstrip('/') + '/'
                    targets.append(line)
            # optional: load JSON template file
            json_template = None
            if args.json_template_path:
                with open(args.json_template_path, 'r', encoding='utf-8') as jf:
                    json_template = json.load(jf)
            # attach template to args for convenience
            args.json_template = json_template
            # set headers to run
            args.headers_to_run = args.headers if args.headers else DEFAULT_HEADERS_TO_FUZZ

            for t in targets:
                outfh.write(f"[*] Fuzzing target: {t} at {time.ctime()}\n")
                outfh.flush()
                await fuzz_url(session, t, args, outfh)


def parse_args():
    p = argparse.ArgumentParser(description='Async parameter fuzzer (GET + JSON POST + header fuzzing)')
    p.add_argument('--input', required=True, help='file with seed urls/hosts (one per line)')
    p.add_argument('--outdir', default='./out', help='output directory')
    p.add_argument('--method', choices=['GET','POST'], default='GET', help='HTTP method to use')
    p.add_argument('--json-template-path', help='path to a JSON template file with __FUZZ__ placeholders (optional)')
    p.add_argument('--concurrency', type=int, default=100, help='global concurrency (not per-target)')
    p.add_argument('--concurrency-per-target', type=int, default=20, help='concurrency per target')
    p.add_argument('--timeout', type=int, default=15, help='request timeout in seconds')
    p.add_argument('--params-to-fuzz', nargs='*', default=COMMON_PARAMS, help='list of parameter names to fuzz for GET')
    p.add_argument('--headers', nargs='*', help='custom header names to fuzz (space separated)')
    p.add_argument('--headers-to-run', nargs='*', help=argparse.SUPPRESS)
    return p.parse_args()


if __name__ == '__main__':
    args = parse_args()
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print('\nInterrupted by user')
