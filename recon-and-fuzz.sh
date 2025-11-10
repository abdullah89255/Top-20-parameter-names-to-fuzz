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
