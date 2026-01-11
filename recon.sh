#!/usr/bin/env bash
set -Eeuo pipefail

########################################
# SCRIPT DIR / PROJECT ROOT (FIXED)
########################################
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

########################################
# HELP
########################################
show_help() {
cat <<EOF
Usage:
  $(basename "$0") <domain> [--from <stage>] [--base-dir <path>]

Stages:
  passive
  bruteforce
  permutations
  dns
  recon_intel
  http_discovery
  http_exploitation
  nuclei
  ffuf
EOF
}

########################################
# ARGS
########################################
domain=""
START_STAGE="all"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) show_help; exit 0 ;;
    --from) START_STAGE="$2"; shift 2 ;;
    --base-dir) OUTPUT_ROOT="$2"; shift 2 ;;
    *) domain="$1"; shift ;;
  esac
done

[[ -z "$domain" ]] && { show_help; exit 1; }

########################################
# STAGES
########################################
STAGES=(passive bruteforce permutations dns recon_intel http_discovery http_exploitation nuclei ffuf)

stage_exists() {
  for s in "${STAGES[@]}"; do [[ "$s" == "$1" ]] && return 0; done
  return 1
}

if [[ "$START_STAGE" != "all" ]] && ! stage_exists "$START_STAGE"; then
  echo "[!] Invalid stage: $START_STAGE"
  exit 1
fi

########################################
# RUN CONTROL
########################################
RUN=false
should_run() {
  local s="$1"
  [[ "$START_STAGE" == "all" ]] && return 0
  [[ "$RUN" == false && "$s" == "$START_STAGE" ]] && RUN=true
  [[ "$RUN" == true ]]
}

########################################
# CONFIG
########################################
HTTP_THREADS=50
HTTP_RATE=120
NUCLEI_CONCURRENCY=30
NUCLEI_RATE=200
NUCLEI_TIMEOUT=10

RESOLVERS="$HOME/resolvers.txt"
WORDLIST="$HOME/wordlists/dns.txt"
ALTDNS_WORDLIST="$HOME/wordlists/altdns_words.txt"
NUCLEI_TEMPLATES="$HOME/nuclei-templates"
AMASS_CONFIG="$HOME/.config/amass/config.yaml"

OUTPUT_ROOT="${OUTPUT_ROOT:-$PROJECT_ROOT/output}"
BASE_DIR="$OUTPUT_ROOT/$domain"

mkdir -p "$BASE_DIR"/{passive,bruteforce,permutations,dns,final,tmp,logs,recon_intel,http_discovery,http_exploitation,nuclei,ffuf}

LOG_FILE="$BASE_DIR/logs/recon.log"
exec >>"$LOG_FILE" 2>&1

log(){ echo "[*] $(date '+%F %T') :: $*"; }
warn(){ echo "[!] $(date '+%F %T') :: $*"; }

safe_cat(){ for f in "$@"; do [[ -s "$f" ]] && cat "$f"; done; }

########################################
# TOOL CHECKS
########################################
log "Checking required tools..."
MISSING_TOOLS=()

for t in subfinder assetfinder amass puredns dnsgen altdns httpx nuclei jq awk sed grep sort cut; do
  if ! command -v "$t" >/dev/null 2>&1; then
    MISSING_TOOLS+=("$t")
  fi
done

if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
  echo ""
  echo "[!] Missing required tools: ${MISSING_TOOLS[*]}"
  exit 1
fi

########################################
# PASSIVE
########################################
if should_run passive; then
  log "STAGE: passive"
  subfinder -d "$domain" -silent -all > "$BASE_DIR/passive/subfinder.txt" || true
  assetfinder --subs-only "$domain" > "$BASE_DIR/passive/assetfinder.txt" || true
  amass enum -passive -d "$domain" -o "$BASE_DIR/passive/amass.txt" || true

  safe_cat "$BASE_DIR/passive/"*.txt | sort -u > "$BASE_DIR/passive/passive_seeds.txt"
  log "Passive seeds: $(wc -l < "$BASE_DIR/passive/passive_seeds.txt" || echo 0)"
fi

########################################
# BRUTEFORCE
########################################
if should_run bruteforce; then
  log "STAGE: bruteforce"

  puredns bruteforce "$WORDLIST" "$domain" -r "$RESOLVERS" -w "$BASE_DIR/bruteforce/raw.txt"
  puredns resolve "$BASE_DIR/bruteforce/raw.txt" -r "$RESOLVERS" \
    --wildcard-tests 3 -w "$BASE_DIR/bruteforce/resolved.txt" || true

  safe_cat "$BASE_DIR/passive/passive_seeds.txt" \
           "$BASE_DIR/bruteforce/resolved.txt" \
    | sort -u > "$BASE_DIR/final/resolved_fqdns.txt"
fi

########################################
# PERMUTATIONS
########################################
if should_run permutations; then
  log "STAGE: permutations"

  dnsgen "$BASE_DIR/final/resolved_fqdns.txt" > "$BASE_DIR/permutations/dnsgen_raw.txt" || true
  grep -E "\.$domain$" "$BASE_DIR/permutations/dnsgen_raw.txt" \
    | sort -u > "$BASE_DIR/permutations/all_permutations.txt"
fi

########################################
# DNS
########################################
if should_run dns; then
  log "STAGE: dns"

  safe_cat "$BASE_DIR/final/resolved_fqdns.txt" \
           "$BASE_DIR/permutations/all_permutations.txt" \
    | sort -u > "$BASE_DIR/dns/all_candidates.txt"

  puredns resolve "$BASE_DIR/dns/all_candidates.txt" \
    -r "$RESOLVERS" --wildcard-tests 5 \
    --write-massdns "$BASE_DIR/tmp/puredns.snl" || true

  awk '{print $1}' "$BASE_DIR/tmp/puredns.snl" | sed 's/\.$//' \
    | sort -u > "$BASE_DIR/dns/resolved_domains.txt"
fi

########################################
# RECON INTEL
########################################
if should_run recon_intel; then
  log "STAGE: recon_intel"

  grep -Eai 'amazonaws|azure|cloudfront|cloudflare|fastly' \
    "$BASE_DIR/dns/resolved_domains.txt" \
    > "$BASE_DIR/recon_intel/cloud_assets.txt" || true
fi

########################################
# HTTP DISCOVERY (FIXED)
########################################
if should_run http_discovery; then
  log "STAGE: http_discovery"

  HTTPX_JSON="$BASE_DIR/http_discovery/httpx_full.json"
  HTTPX_TXT="$BASE_DIR/http_discovery/httpx_full.txt"

  httpx -l "$BASE_DIR/dns/resolved_domains.txt" \
    -threads "$HTTP_THREADS" \
    -rate-limit "$HTTP_RATE" \
    -status-code -title -tech-detect \
    -follow-redirects \
    -json -silent \
    -o "$HTTPX_JSON" || true

  if [[ -s "$HTTPX_JSON" ]]; then
    jq -r '
      .url as $u
      | (.status_code // "") as $s
      | (.title // "") as $t
      | (.tech // []) as $tech
      | "\($u) [\($s)] [\($t)] [\($tech|join(\",\"))]"
    ' "$HTTPX_JSON" > "$HTTPX_TXT" || true

    jq -r '.url' "$HTTPX_JSON" | sort -u \
      > "$BASE_DIR/http_discovery/live_urls.txt"

    jq -r 'select(.status_code==200) | .url' "$HTTPX_JSON" \
      > "$BASE_DIR/http_discovery/status_200.txt"

    jq -r 'select(.status_code==401) | .url' "$HTTPX_JSON" \
      > "$BASE_DIR/http_discovery/status_401.txt"

    jq -r 'select(.status_code==403) | .url' "$HTTPX_JSON" \
      > "$BASE_DIR/http_discovery/status_403.txt"

    jq -r '.tech[]?' "$HTTPX_JSON" | sort -u \
      > "$BASE_DIR/http_discovery/technologies.txt"
  else
    : > "$BASE_DIR/http_discovery/live_urls.txt"
  fi

  log "Live HTTP services: $(wc -l < "$BASE_DIR/http_discovery/live_urls.txt" || echo 0)"
fi

########################################
# HTTP EXPLOITATION
########################################
if should_run http_exploitation; then
  log "STAGE: http_exploitation"

  grep -Eai '(admin|api|auth|login|dashboard|panel|console)' \
    "$BASE_DIR/http_discovery/live_urls.txt" \
    | sort -u > "$BASE_DIR/http_exploitation/high_value_urls.txt" || true
fi

#####################################
#NUCLEI SCAN
#####################################
if should_run nuclei; then
  log "STAGE: nuclei"

  # Update templates
  nuclei -update-templates -silent || true

  ########################################
  # Helper function for controlled scans
  ########################################
  run_nuclei_scan() {
    local targets="$1"
    local templates="$2"
    local severity="$3"
    local output="$4"
    local description="$5"
    local exclude_tags="${6:-}"

    if [[ ! -s "$targets" ]]; then
      warn "Skipping $description (no targets)"
      return
    fi

    log "Starting Nuclei: $description ($(wc -l < "$targets") targets)"

    local cmd=(
      nuclei
      -l "$targets"
      -t "$templates"
      -severity "$severity"
      -c "$NUCLEI_CONCURRENCY"
      -rl "$NUCLEI_RATE"
      -timeout "$NUCLEI_TIMEOUT"
      -retries 1
      -silent
      -no-color
      -o "$output"
    )

    [[ -n "$exclude_tags" ]] && cmd+=(-exclude-tags "$exclude_tags")

    timeout 1800 "${cmd[@]}" 2>"${output%.txt}_error.log" || {
      warn "Nuclei scan failed or timed out: $description"
    }

    log "$description finished ($(wc -l < "$output" 2>/dev/null || echo 0) findings)"
  }

  ########################################
  # 1. SUBDOMAIN TAKEOVERS (HIGHEST PRIORITY)
  ########################################
  run_nuclei_scan \
    "$BASE_DIR/recon_intel/takeover_candidates.txt" \
    "$NUCLEI_TEMPLATES/http/takeovers/,$NUCLEI_TEMPLATES/dns/" \
    "info,low,medium,high,critical" \
    "$BASE_DIR/nuclei/takeovers.txt" \
    "Subdomain Takeover Scan"

  ########################################
  # 2. HIGH-VALUE CVEs (ADMIN / API / AUTH)
  ########################################
  run_nuclei_scan \
    "$BASE_DIR/http_exploitation/high_value_urls.txt" \
    "$NUCLEI_TEMPLATES/cves/,$NUCLEI_TEMPLATES/vulnerabilities/,$NUCLEI_TEMPLATES/exposures/" \
    "high,critical" \
    "$BASE_DIR/nuclei/high_value_cves.txt" \
    "High-Value CVE Scan"

  ########################################
  # 3. EXPOSED PANELS & DEFAULT LOGINS
  ########################################
  run_nuclei_scan \
    "$BASE_DIR/http_discovery/live_urls.txt" \
    "$NUCLEI_TEMPLATES/exposed-panels/,$NUCLEI_TEMPLATES/default-logins/" \
    "medium,high,critical" \
    "$BASE_DIR/nuclei/exposed_panels.txt" \
    "Exposed Panels & Default Logins"

  ########################################
  # 4. MISCONFIGURATIONS (SAFE ONLY)
  ########################################
  run_nuclei_scan \
    "$BASE_DIR/http_discovery/live_urls.txt" \
    "$NUCLEI_TEMPLATES/misconfiguration/,$NUCLEI_TEMPLATES/exposures/" \
    "medium,high,critical" \
    "$BASE_DIR/nuclei/misconfigurations.txt" \
    "Misconfiguration Scan" \
    "dos,fuzz,intrusive"

  ########################################
  # 5. FULL SCAN (ONLY IF SCOPE IS SMALL)
  ########################################
  LIVE_COUNT=$(wc -l < "$BASE_DIR/http_discovery/live_urls.txt" 2>/dev/null || echo 0)

  if [[ "$LIVE_COUNT" -gt 0 && "$LIVE_COUNT" -le 500 ]]; then
    run_nuclei_scan \
      "$BASE_DIR/http_discovery/live_urls.txt" \
      "$NUCLEI_TEMPLATES/" \
      "low,medium,high,critical" \
      "$BASE_DIR/nuclei/comprehensive.txt" \
      "Comprehensive Scan" \
      "dos,fuzz,intrusive"
  else
    log "Skipping comprehensive scan ($LIVE_COUNT targets)"
  fi

  ########################################
  # AGGREGATE HIGH & CRITICAL FINDINGS
  ########################################
  {
    grep -Ei 'critical|high' "$BASE_DIR/nuclei/"*.txt 2>/dev/null
  } | sort -u > "$BASE_DIR/nuclei/CRITICAL_FINDINGS.txt" || true

  log "Nuclei stage completed"
  log "Critical findings: $(wc -l < "$BASE_DIR/nuclei/CRITICAL_FINDINGS.txt" 2>/dev/null || echo 0)"
fi


########################################
# FFUF
########################################
if should_run ffuf; then
  log "STAGE: ffuf"
  ffuf -w "$WORDLIST" -u "https://FUZZ.$domain" -mc 200 \
    -o "$BASE_DIR/ffuf/results.json" || true
fi

########################################
# SUMMARY
########################################
log "================================================"
log "Recon Summary for $domain"
log "Live URLs: $(wc -l < "$BASE_DIR/http_discovery/live_urls.txt" || echo 0)"
log "Critical findings: $(wc -l < "$BASE_DIR/nuclei/CRITICAL_FINDINGS.txt" || echo 0)"
log "================================================"

echo ""
echo "[✓] Recon completed for $domain"
echo "Results: $BASE_DIR"
