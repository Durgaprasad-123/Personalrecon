#!/bin/bash

# =========================
# USAGE
# =========================
if [ $# -lt 1 ]; then
  echo "Usage:"
  echo "  $0 <targets_file> [wordlist1 wordlist2 ...]"
  exit 1
fi

TARGETS_FILE="$1"
shift
USER_WORDLISTS=("$@")

OUTPUT_DIR="ffuf-results"
THREADS=30
TIMEOUT=10
USER_AGENT="Mozilla/5.0 (X11; Linux x86_64)"

# Default curated wordlists
DEFAULT_WORDLISTS=(
  "/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-directories.txt"
  "/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt"
  "/usr/share/wordlists/SecLists/Discovery/Web-Content/api/api-endpoints.txt"
)

# =========================
# CHECK TARGET FILE
# =========================
if [ ! -f "$TARGETS_FILE" ]; then
  echo "[-] Targets file not found: $TARGETS_FILE"
  exit 1
fi

# =========================
# WORDLIST SELECTION
# =========================
if [ ${#USER_WORDLISTS[@]} -gt 0 ]; then
  WORDLISTS=("${USER_WORDLISTS[@]}")
  echo "[+] Using user-provided wordlists"
else
  WORDLISTS=("${DEFAULT_WORDLISTS[@]}")
  echo "[+] Using default curated wordlists"
fi

# =========================
# WORDLIST VALIDATION
# =========================
MISSING_WORDLISTS=0

for WL in "${WORDLISTS[@]}"; do
  if [ ! -f "$WL" ]; then
    echo "[-] Missing wordlist: $WL"
    MISSING_WORDLISTS=1
  fi
done

if [ "$MISSING_WORDLISTS" -eq 1 ]; then
  echo
  echo "[!] One or more wordlists are missing."
  echo "[!] Install required wordlists using:"
  echo
  echo "    sudo apt update"
  echo "    sudo apt install seclists"
  echo
  echo "    # OR manually clone"
  echo "    git clone https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/SecLists"
  echo
  exit 1
fi

# =========================
# START SCANNING
# =========================
mkdir -p "$OUTPUT_DIR"

echo
echo "[+] Starting ffuf scans"
echo

awk '{print $1}' "$TARGETS_FILE" | sort -u | while read -r URL; do
  DOMAIN=$(echo "$URL" | sed 's|https\?://||g' | tr '/' '_')
  DOMAIN_DIR="$OUTPUT_DIR/$DOMAIN"
  mkdir -p "$DOMAIN_DIR"

  echo "[*] Target: $URL"

  for WORDLIST in "${WORDLISTS[@]}"; do
    WL_NAME=$(basename "$WORDLIST")
    OUTPUT_FILE="$DOMAIN_DIR/${WL_NAME}.json"

    echo "    [+] Wordlist: $WL_NAME"

    ffuf -u "$URL/FUZZ" \
      -w "$WORDLIST" \
      -H "User-Agent: $USER_AGENT" \
      -t "$THREADS" \
      -timeout "$TIMEOUT" \
      -ac \
      -fc 404,429 \
      -mc 200,204,301,302,307,401,403,405,500 \
      -o "$OUTPUT_FILE" \
      -of json \
      -silent
  done

  echo

done

echo "[+] ffuf scanning completed"
