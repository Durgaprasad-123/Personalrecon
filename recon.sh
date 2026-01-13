#!/usr/bin/env bash

set -Eeuo pipefail

########################################
# SCRIPT DIR / PROJECT ROOT (FIXED)
########################################
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
NO_COLOR=false

########################################
# DEBUG (shows where it fails if it does)
########################################
#set -x   # uncomment only if debugging

########################################
# TIMERS & SPINNER
########################################
_timer_start=0
_spinner_pid=""

start_timer() {
  _timer_start=$(date +%s)
}

end_timer() {
  local end=$(date +%s)
  echo "$((end - _timer_start))s"
}

spinner() {
  local msg="$1"
  local i=0
  local sp='|/-\'

  tput civis 2>/dev/null || true      # hide cursor

  while :; do
    printf '\r%s[+] %s %s%s' "$GREEN" "$msg" "${sp:i++%4:1}" "$NC" >&2
    sleep 0.1
  done
}

start_spinner() {
  spinner "$1" &
  _spinner_pid=$!
  disown
}

stop_spinner() {
  if [[ -n "${_spinner_pid:-}" ]]; then
    kill "$_spinner_pid" 2>/dev/null
    wait "$_spinner_pid" 2>/dev/null || true
    _spinner_pid=""
    printf "\r\033[K" >&2   # clear entire line
    tput cnorm 2>/dev/null || true   # restore cursor
  fi
}

run_tool() {
  local desc="$1"
  shift

  start_timer
  start_spinner "$desc"

  if "$@"; then
    stop_spinner
    info "$desc completed in $(end_timer)"
  else
    stop_spinner
    warn "$desc failed after $(end_timer)"
    return 1
  fi
}

########################################
# STAGE HELPERS
########################################
stage_start() {
  CURRENT_STAGE="$1"
  echo
  log "==================== STAGE START: $1 ===================="
}

stage_end() {
  log "==================== STAGE END: $1 ===================="
  echo
}

########################################
# TUI COLORS (INIT AFTER ARGS)
########################################
init_colors() {
  if [[ -t 1 && "$NO_COLOR" == false ]]; then
    BLUE=$'\033[1;34m'
    GREEN=$'\033[1;32m'
    RED=$'\033[1;31m'
    YELLOW=$'\033[1;33m'
    NC=$'\033[0m'
  else
    BLUE='' GREEN='' RED='' YELLOW='' NC=''
  fi
}

########################################
# HELP
########################################
show_help() {
cat <<EOF
Usage:
  $(basename "$0") <domain> [--from <stage>] [--base-dir <path>] [--no-color]

Options:
  --from <stage>     Start from a specific stage
  --base-dir <path>  Set custom output directory
  --no-color         Disable colors for the output & logs on the TTY

Stages:
  passive            - Passive subdomain enumeration
  bruteforce         - DNS bruteforce with wordlists
  permutations       - Generate domain permutations
  dns                - DNS resolution and validation
  recon_intel        - Cloud assets and takeover detection
  http_discovery     - HTTP probing and tech detection
  http_exploitation  - High-value target identification
  nuclei             - Vulnerability scanning
  ffuf               - Fuzzing (optional)

Example:
  ./recon.sh example.com
  ./recon.sh example.com --from passive
  ./recon.sh example.com --base-dir /custom/path      
  ./recon.sh example.com --no-color                   

Output:
  Results are saved to: output/<domain>/
  Final report: output/<domain>/FINAL_REPORT.txt
  Logs: output/<domain>/logs/recon.log
EOF
}

########################################
# CLEAN EXIT HANDLING
########################################
CURRENT_STAGE="init"
INTERRUPTED=false

cleanup() {
  stop_spinner
  printf '\033[0m' >&2    # hard reset colors
  tput cnorm 2>/dev/null || true

  echo >&2
  warn "Interrupted during stage: $CURRENT_STAGE"
  warn "Partial results saved in: $BASE_DIR"
  echo "$RED[x] Recon aborted by user (CTRL+C)"
  exit 130
}

trap cleanup SIGINT SIGTERM

########################################
# ARGS
########################################
domain=""
START_STAGE="all"


while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      show_help; exit 0 ;;
    --from)
      START_STAGE="$2"; shift 2 ;;
    --base-dir)
      OUTPUT_ROOT="$2"; shift 2 ;;
    --no-color)
      NO_COLOR=true; shift ;;
    *)
      domain="$1"; shift ;;
  esac
done

[[ -z "$domain" ]] && { show_help; exit 1; }

init_colors

########################################
# STAGES
########################################
STAGES=(passive bruteforce permutations dns recon_intel http_discovery http_exploitation nuclei ffuf)

stage_exists() {
  for s in "${STAGES[@]}"; do
    [[ "$s" == "$1" ]] && return 0
  done
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
# CONFIG (FIXED OUTPUT ROOT)
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

mkdir -p "$BASE_DIR"/{passive,bruteforce,labels,permutations,dns,final,tmp,logs,recon_intel,http_discovery,http_exploitation,nuclei,ffuf}

LOG_FILE="$BASE_DIR/logs/recon.log"
mkdir -p "$(dirname "$LOG_FILE")"
# redirection and printing the log to the terminal
exec > >(tee -a "$LOG_FILE") 2>&1

# Just for more verbose on the operations, added info logs
log(){
  echo -e "${BLUE}[*] $(date '+%F %T') :: $*${NC}"
}

info(){
  echo -e "${GREEN}[+] $(date '+%F %T') :: $*${NC}"
}

warn(){
  echo -e "${RED}[!] $(date '+%F %T') :: $*${NC}"
}


safe_cat(){ for f in "$@"; do [[ -s "$f" ]] && cat "$f"; done; }

need(){
  [[ -s "$1" ]] || { warn "Missing dependency: $1 (run $2)"; exit 1; }
}

########################################
# TOOL CHECKS
########################################
for t in subfinder assetfinder amass puredns dnsgen altdns httpx nuclei awk sed grep sort cut; do
  command -v "$t" >/dev/null || { echo "[!] Missing tool: $t"; exit 1; }
done

########################################
# PASSIVE
########################################
# Added some informative logs and removed all the 'true' statement and replaced them with the warnings for verbose
if should_run passive; then
  stage_start passive

  info "Running subfinder..."
  subfinder -d "$domain" -silent -all > "$BASE_DIR/passive/subfinder.txt" || warn "subfinder failed !"
  
  info "Running assetfinder..."
  assetfinder --subs-only "$domain" > "$BASE_DIR/passive/assetfinder.txt" || warn "assetfinder failed !"
  
  info "Running amass passive..."
  amass enum -passive -d "$domain" -o "$BASE_DIR/passive/amass.txt" || warn "amass failed !"

  safe_cat "$BASE_DIR/passive/"*.txt | sort -u \
    > "$BASE_DIR/passive/passive_seeds.txt"

  log "Passive results: $(wc -l < "$BASE_DIR/passive/passive_seeds.txt" 2>/dev/null || echo 0)"
  stage_end passive
fi

########################################
# BRUTEFORCE
########################################
if should_run bruteforce; then
  stage_start bruteforce

  [[ -s "$WORDLIST" ]] || { warn "WORDLIST missing: $WORDLIST"; exit 1; }
  [[ -s "$RESOLVERS" ]] || { warn "RESOLVERS missing: $RESOLVERS"; exit 1; }

  run_tool "Running puredns bruteforce" \
    puredns bruteforce "$WORDLIST" "$domain" \
      -r "$RESOLVERS" \
      --rate-limit-trusted 400 \
      -w "$BASE_DIR/bruteforce/raw.txt" \
      --quiet

  if [[ -s "$BASE_DIR/bruteforce/raw.txt" ]]; then
    run_tool "Resolving bruteforce results" \
      puredns resolve "$BASE_DIR/bruteforce/raw.txt" \
        -r "$RESOLVERS" \
        --wildcard-tests 3 \
        -w "$BASE_DIR/bruteforce/resolved.txt" \
        --quiet
  else
    warn "No bruteforce output generated — skipping resolve"
  fi

  info "Merging passive and bruteforce results"
  safe_cat "$BASE_DIR/passive/passive_seeds.txt" \
           "$BASE_DIR/bruteforce/resolved.txt" \
    | sort -u > "$BASE_DIR/final/resolved_fqdns.txt"

  info "Resolved FQDNs: $(wc -l < "$BASE_DIR/final/resolved_fqdns.txt" 2>/dev/null || echo 0)"
  stage_end bruteforce
fi


########################################
# PERMUTATIONS
########################################
if should_run permutations; then
  stage_start permutations

  if [[ ! -s "$BASE_DIR/final/resolved_fqdns.txt" ]]; then
    warn "resolved_fqdns.txt missing — run bruteforce first"
    exit 1
  fi

  run_tool "Generating permutations with dnsgen" \
    bash -c 'dnsgen "$1" | sed "s/\.$2$//" | sort -u > "$3"' \
     _ "$BASE_DIR/final/resolved_fqdns.txt" "$domain" "$BASE_DIR/permutations/dnsgen_labels.txt"

  info "Extracting service root labels"
  sed "s/\\.$domain\$//" "$BASE_DIR/final/resolved_fqdns.txt" \
    | cut -d'.' -f1 | sort -u \
    > "$BASE_DIR/labels/service_roots.txt"

  if [[ -s "$ALTDNS_WORDLIST" && -s "$BASE_DIR/labels/service_roots.txt" ]]; then
    run_tool "Generating permutations with altdns" \
      altdns -i "$BASE_DIR/labels/service_roots.txt" \
             -w "$ALTDNS_WORDLIST" \
             -o "$BASE_DIR/permutations/altdns_labels.txt" \
             -t 507
    warn "Skipping altdns (missing wordlist or service roots)"
    : > "$BASE_DIR/permutations/altdns_labels.txt"
  fi

  info "Normalizing and validating labels"
  {
    [[ -s "$BASE_DIR/permutations/dnsgen_labels.txt" ]] && cat "$BASE_DIR/permutations/dnsgen_labels.txt"
    [[ -s "$BASE_DIR/permutations/altdns_labels.txt" ]] && cat "$BASE_DIR/permutations/altdns_labels.txt"
  } | grep -E '^[a-z0-9][a-z0-9-]{1,30}$' \
    | sort -u > "$BASE_DIR/permutations/all_labels.txt"

  if [[ -s "$BASE_DIR/permutations/all_labels.txt" ]]; then
    info "Building permutation FQDN list"
    sed "s/$/.$domain/" "$BASE_DIR/permutations/all_labels.txt" \
      > "$BASE_DIR/permutations/fqdns.txt"

    info "Permutation FQDNs: $(wc -l < "$BASE_DIR/permutations/fqdns.txt")"
  else
    warn "No valid permutation labels generated"
  fi
  stage_end permutations
fi

########################################
# DNS
########################################
if should_run dns; then
  stage_start dns

  info "Preparing DNS input list"
  safe_cat "$BASE_DIR/final/resolved_fqdns.txt" \
           "$BASE_DIR/permutations/fqdns.txt" \
    | sort -u > "$BASE_DIR/final/final_dns.txt"

  if [[ -s "$BASE_DIR/final/final_dns.txt" ]]; then
    run_tool "Resolving DNS with puredns" \
      puredns resolve "$BASE_DIR/final/final_dns.txt" \
        -r "$RESOLVERS" \
        --wildcard-tests 5 \
        --write-massdns "$BASE_DIR/tmp/puredns.snl"
  else
    warn "No DNS names to resolve — skipping puredns"
  fi

  if [[ -s "$BASE_DIR/tmp/puredns.snl" ]]; then
    info "Extracting DNS records"
    awk '{print $1, $3}' "$BASE_DIR/tmp/puredns.snl" \
      | sed 's/\.$//' | sort -u \
      > "$BASE_DIR/final/dns_records.txt"

    info "Building DNS → IP map"
    awk '{print $1, $3}' "$BASE_DIR/tmp/puredns.snl" \
      | sed 's/\.$//' | sort -u \
      > "$BASE_DIR/final/dns_ip_map.txt"
  else
    warn "No puredns output found — DNS records not generated"
  fi
  stage_end dns
fi


########################################
# RECON INTEL
########################################
if should_run recon_intel; then
  stage_start recon_intel

  if [[ -s "$BASE_DIR/final/dns_records.txt" ]]; then
    info "Extracting cloud assets"
    grep -Eai 'amazonaws|azure|cloudfront|googleusercontent' \
      "$BASE_DIR/final/dns_records.txt" \
      > "$BASE_DIR/recon_intel/cloud_assets.txt" \
      || warn "No cloud assets identified"

    info "Extracting takeover candidates"
    grep -Eai 'herokuapp|github.io|s3.amazonaws.com|fastly.net|azurewebsites.net' \
      "$BASE_DIR/final/dns_records.txt" \
      | awk '{print $1}' \
      > "$BASE_DIR/recon_intel/takeover_candidates.txt" \
      || warn "No takeover candidates identified"
  else
    warn "dns_records.txt missing — skipping recon_intel"
  fi
  stage_end recon_intel
fi

########################################
# HTTP DISCOVERY
########################################
if should_run http_discovery; then
  stage_start http_discovery

  HTTPX_JSON="$BASE_DIR/http_discovery/httpx_full.json"
  HTTPX_TXT="$BASE_DIR/http_discovery/httpx_full.txt"
  LIVE_URLS="$BASE_DIR/http_discovery/live_urls.txt"

  [[ -s "$BASE_DIR/dns/resolved_domains.txt" ]] || {
    warn "No DNS input for httpx — skipping HTTP discovery"
    stage_end http_discovery
    :   # no-op, safely continues
  }

  run_tool "Probing HTTP services with httpx" \
    httpx -l "$BASE_DIR/dns/resolved_domains.txt" \
      -threads "$HTTP_THREADS" \
      -rate-limit "$HTTP_RATE" \
      -status-code -title -tech-detect \
      -follow-redirects \
      -json -silent \
      -o "$HTTPX_JSON" \
    || warn "httpx probe failed"

  ########################################
  # POST-PROCESS RESULTS
  ########################################
  if [[ -s "$HTTPX_JSON" ]]; then
    info "Parsing httpx results"

    jq -r '
      .url as $u
      | (.status_code // "") as $s
      | (.title // "") as $t
      | (.tech // []) as $tech
      | "\($u) [\($s)] [\($t)] [\($tech|join(","))]"
    ' "$HTTPX_JSON" > "$HTTPX_TXT" || warn "Failed to generate text output"

    jq -r '.url' "$HTTPX_JSON" | sort -u > "$LIVE_URLS"

    jq -r 'select(.status_code==200) | .url' "$HTTPX_JSON" \
      > "$BASE_DIR/http_discovery/status_200.txt"

    jq -r 'select(.status_code==401) | .url' "$HTTPX_JSON" \
      > "$BASE_DIR/http_discovery/status_401.txt"

    jq -r 'select(.status_code==403) | .url' "$HTTPX_JSON" \
      > "$BASE_DIR/http_discovery/status_403.txt"

    jq -r '.tech[]?' "$HTTPX_JSON" | sort -u \
      > "$BASE_DIR/http_discovery/technologies.txt"
  else
    warn "httpx produced no output"
    : > "$LIVE_URLS"
  fi

  info "Live HTTP services: $(wc -l < "$LIVE_URLS" 2>/dev/null || echo 0)"

  stage_end http_discovery
fi


########################################
# HTTP EXPLOITATION
########################################
if should_run http_exploitation; then
  stage_start http_exploitation

  if [[ -s "$BASE_DIR/http_discovery/live_urls.txt" ]]; then
    info "Identifying high-value endpoints"
    grep -Eai '(admin|api|auth|login|dashboard)' \
      "$BASE_DIR/http_discovery/live_urls.txt" \
      | sort -u > "$BASE_DIR/http_exploitation/high_value_urls.txt" \
      || warn "No high-value URLs found"
  else
    warn "live_urls.txt missing — skipping HTTP exploitation"
  fi
  stage_end http_exploitation
fi

########################################
# NUCLEI
########################################
if should_run nuclei; then
  stage_start nuclei

  info "Updating Nuclei templates"
  nuclei -update-templates -silent || warn "Template update failed"

  ########################################
  # Helper: Controlled nuclei scan w/ spinner
  ########################################
  run_nuclei_scan() {
    local targets="$1"
    local templates="$2"
    local severity="$3"
    local output="$4"
    local description="$5"
    local exclude_tags="${6:-}"

    [[ ! -s "$targets" ]] && {
      warn "Skipping $description (no targets)"
      return
    }

    local count
    count=$(wc -l < "$targets" 2>/dev/null || echo 0)
    info "$description — $count targets"

    local cmd=(
      timeout 1800
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

    run_tool "$description" \
      "${cmd[@]}" 2>"${output%.txt}_error.log" \
      || warn "Nuclei scan failed or timed out: $description"

    info "$description findings: $(wc -l < "$output" 2>/dev/null || echo 0)"
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
  info "Aggregating critical findings"
  {
    grep -Ei 'critical|high' "$BASE_DIR/nuclei/"*.txt 2>/dev/null
  } | sort -u > "$BASE_DIR/nuclei/CRITICAL_FINDINGS.txt" || true

  info "Critical findings: $(wc -l < "$BASE_DIR/nuclei/CRITICAL_FINDINGS.txt" 2>/dev/null || echo 0)"

  stage_end nuclei
fi

########################################
# FFUF
########################################
if should_run ffuf; then
  stage_start ffuf

  # Safeguard to check for the wordlist folder making sure it's not empty
  if [[ -s "$WORDLIST" ]]; then
    run_tool "Running ffuf fuzzing" \
      ffuf -w "$WORDLIST" \
           -u "https://FUZZ.$domain" \
           -mc 200 \
           -o "$BASE_DIR/ffuf/results.json" \
      || warn "ffuf scan failed"
  else
    warn "WORDLIST missing — skipping ffuf"
  fi
  stage_end ffuf
fi



########################################
# SUMMARY
########################################
log "================================================"
log "Recon Summary for $domain"
log "Live URLs: $(wc -l < "$BASE_DIR/http_discovery/live_urls.txt" || echo 0)"
log "Critical findings: $(wc -l < "$BASE_DIR/nuclei/CRITICAL_FINDINGS.txt" || echo 0)"
log "================================================"


log "Recon completed for $domain"
info "Output directory: $BASE_DIR"
echo "$GREEN [✓] Recon completed for $NC $domain"

########################################
# FINAL REPORT
########################################
FINAL_REPORT="$BASE_DIR/FINAL_REPORT.txt"

info "Generating final reconnaissance report"

{
  echo "================================================================="
  echo "Reconnaissance Report"
  echo "Target Domain : $domain"
  echo "Date          : $(date '+%F %T')"
  echo "================================================================="
  echo ""

  echo "DISCOVERY STATISTICS"
  echo "-------------------"
  echo "Resolved Domains       : $(wc -l < "$BASE_DIR/final/final_dns.txt" 2>/dev/null || echo 0)"
  echo "Live HTTP Services     : $(wc -l < "$BASE_DIR/http_discovery/live_urls.txt" 2>/dev/null || echo 0)"
  echo "Technologies Detected  : $(wc -l < "$BASE_DIR/http_discovery/technologies.txt" 2>/dev/null || echo 0)"
  echo ""

  echo "HIGH-VALUE TARGETS"
  echo "------------------"
  echo "Admin/API/Auth Endpoints: $(wc -l < "$BASE_DIR/http_exploitation/high_value_urls.txt" 2>/dev/null || echo 0)"
  if [[ -s "$BASE_DIR/http_exploitation/high_value_urls.txt" ]]; then
    echo ""
    echo "Top Endpoints:"
    head -20 "$BASE_DIR/http_exploitation/high_value_urls.txt"
  else
    echo "None identified"
  fi
  echo ""

  echo "SECURITY FINDINGS"
  echo "-----------------"
  echo "Critical / High Severity Issues: $(wc -l < "$BASE_DIR/nuclei/CRITICAL_FINDINGS.txt" 2>/dev/null || echo 0)"
  if [[ -s "$BASE_DIR/nuclei/CRITICAL_FINDINGS.txt" ]]; then
    echo ""
    echo "Top Findings:"
    head -20 "$BASE_DIR/nuclei/CRITICAL_FINDINGS.txt"
  else
    echo "No critical findings detected"
  fi
  echo ""

  echo "CLOUD & INFRASTRUCTURE"
  echo "---------------------"
  echo "Cloud-hosted Assets      : $(wc -l < "$BASE_DIR/recon_intel/cloud_assets.txt" 2>/dev/null || echo 0)"
  echo "Potential Takeovers      : $(wc -l < "$BASE_DIR/recon_intel/takeover_candidates.txt" 2>/dev/null || echo 0)"
  echo ""

  echo "OUTPUT"
  echo "------"
  echo "Results Directory : $BASE_DIR"
  echo "Log File          : $LOG_FILE"
  echo ""

  echo "================================================================="
  echo "End of Report"
  echo "================================================================="
} > "$FINAL_REPORT"

info "Final report written to: $FINAL_REPORT"
