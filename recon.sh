#!/usr/bin/env bash
set -Eeuo pipefail

########################################
# COLORS & FORMATTING
########################################
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

########################################
# SCRIPT DIR / PROJECT ROOT
########################################
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

########################################
# LOGGING FUNCTIONS
########################################
log() {
  echo -e "${BLUE}[*]${RESET} $(date '+%F %T') :: $*"
}

success() {
  echo -e "${GREEN}[✓]${RESET} $(date '+%F %T') :: $*"
}

warn() {
  echo -e "${YELLOW}[!]${RESET} $(date '+%F %T') :: $*"
}

error() {
  echo -e "${RED}[✗]${RESET} $(date '+%F %T') :: $*"
}

stage_header() {
  local stage_num="$1"
  local stage_name="$2"
  echo ""
  echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${RESET}"
  echo -e "${CYAN}║${RESET} ${BOLD}Stage $stage_num: $(printf '%-52s' "$stage_name")${RESET}${CYAN}║${RESET}"
  echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${RESET}"
}

progress() {
  echo -e "${MAGENTA}  ▸${RESET} $*"
}

safe_cat() {
  for f in "$@"; do
    [[ -s "$f" ]] && cat "$f"
  done
}

########################################
# CLEANUP ON EXIT
########################################
cleanup() {
  local exit_code=$?
  echo ""
  if [[ $exit_code -ne 0 ]]; then
    echo -e "${RED}[✗]${RESET} Script interrupted or failed (exit code: $exit_code)"
    echo -e "${YELLOW}[i]${RESET} Partial results saved to: ${CYAN}${BASE_DIR:-output}${RESET}"
    echo -e "${YELLOW}[i]${RESET} Resume with: ${BOLD}$0 ${domain:-<domain>} --from <stage>${RESET}"
  fi
  [[ -n "${LOG_FILE:-}" ]] && echo "$(date '+%F %T') :: Script ended with exit code: $exit_code" >> "$LOG_FILE" 2>/dev/null || true
}

trap cleanup EXIT
trap 'exit 130' INT TERM

########################################
# HELP
########################################
show_help() {
  echo -e "${BOLD}${CYAN}════════════════════════════════════════════════════════════╗${RESET}"
  echo -e "${BOLD}  Automated Reconnaissance Script (AGGRESSIVE)${RESET}"
  echo -e "${CYAN}════════════════════════════════════════════════════════════╝${RESET}"
  echo ""
  echo -e "${BOLD}Usage:${RESET}"
  echo -e "  $(basename "$0") ${GREEN}<domain>${RESET} [${YELLOW}OPTIONS${RESET}]"
  echo ""
  echo -e "${BOLD}Options:${RESET}"
  echo -e "  ${GREEN}--from <stage>${RESET}     Start from a specific stage"
  echo -e "  ${GREEN}--base-dir <path>${RESET}  Set custom output directory"
  echo -e "  ${GREEN}--verbose, -v${RESET}      Enable verbose output"
  echo -e "  ${GREEN}--nuclei${RESET}           Alias for --from nuclei"
  echo ""
  echo -e "${BOLD}Stages:${RESET}"
  echo -e "  ${CYAN}passive${RESET}            Passive subdomain enumeration"
  echo -e "  ${CYAN}bruteforce${RESET}         DNS bruteforce with wordlists"
  echo -e "  ${CYAN}permutations${RESET}       Generate domain permutations"
  echo -e "  ${CYAN}dns${RESET}                DNS resolution and validation"
  echo -e "  ${CYAN}recon_intel${RESET}        Cloud assets and takeover detection"
  echo -e "  ${CYAN}http_discovery${RESET}     HTTP probing and tech detection"
  echo -e "  ${CYAN}nuclei${RESET}             AGGRESSIVE vulnerability scanning (MEDIUM+ only)"
  echo ""
  echo -e "${BOLD}Examples:${RESET}"
  echo -e "  $(basename "$0") ${GREEN}example.com${RESET}"
  echo -e "  $(basename "$0") ${GREEN}example.com${RESET} ${YELLOW}--nuclei -v${RESET}"
  echo -e "  $(basename "$0") ${GREEN}example.com${RESET} ${YELLOW}--from dns${RESET}"
  echo ""
}

########################################
# ARGS
########################################
domain=""
START_STAGE="all"
VERBOSE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      show_help
      exit 0
      ;;
    --from)
      START_STAGE="$2"
      shift 2
      ;;
    --nuclei)
      START_STAGE="nuclei"
      shift
      ;;
    --base-dir)
      OUTPUT_ROOT="$2"
      shift 2
      ;;
    --verbose|-v)
      VERBOSE=true
      shift
      ;;
    -*)
      error "Unknown option: $1"
      show_help
      exit 1
      ;;
    *)
      domain="$1"
      shift
      ;;
  esac
done

if [[ -z "$domain" ]]; then
  show_help
  exit 1
fi

########################################
# STAGES
########################################
STAGES=(passive bruteforce permutations dns recon_intel http_discovery nuclei)

stage_exists() {
  for s in "${STAGES[@]}"; do
    [[ "$s" == "$1" ]] && return 0
  done
  return 1
}

if [[ "$START_STAGE" != "all" ]] && ! stage_exists "$START_STAGE"; then
  error "Invalid stage: ${YELLOW}$START_STAGE${RESET}"
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

# Nuclei will be configured dynamically based on target count
NUCLEI_BASE_CONCURRENCY=50
NUCLEI_BASE_RATE=300
NUCLEI_TIMEOUT=15
NUCLEI_MAX_HOST_ERROR=30

RESOLVERS="$HOME/resolvers.txt"
WORDLIST="$HOME/wordlists/dns.txt"
NUCLEI_TEMPLATES="$HOME/nuclei-templates"
CUSTOM_NUCLEI_TEMPLATES="$HOME/custom-nuclei-templates"

OUTPUT_ROOT="${OUTPUT_ROOT:-$PROJECT_ROOT/output}"
BASE_DIR="$OUTPUT_ROOT/$domain"

mkdir -p "$BASE_DIR"/{passive,bruteforce,permutations,dns,final,tmp,logs,recon_intel,http_discovery,nuclei/{raw,processed,json}}

LOG_FILE="$BASE_DIR/logs/recon.log"
if [[ "$VERBOSE" == true ]]; then
  exec > >(tee -a "$LOG_FILE") 2>&1
else
  exec >>"$LOG_FILE" 2>&1
fi

########################################
# BANNER
########################################
clear
echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║${RESET}     ${BOLD}${GREEN}AGGRESSIVE RECONNAISSANCE FRAMEWORK (MEDIUM+ ONLY)${RESET}     ${CYAN}║${RESET}"
echo -e "${CYAN}╠════════════════════════════════════════════════════════════╣${RESET}"
echo -e "${CYAN}║${RESET}  Target: ${YELLOW}${BOLD}$(printf '%-50s' "$domain")${RESET} ${CYAN}║${RESET}"
echo -e "${CYAN}║${RESET}  Output: ${DIM}$(printf '%-50s' "$BASE_DIR")${RESET} ${CYAN}║${RESET}"
echo -e "${CYAN}║${RESET}  BY:     ${BOLD}${GREEN}PRASAD${RESET}                                          ${CYAN}║${RESET}"
echo -e "${CYAN}║${RESET}  Mode:   ${BOLD}${RED}HIGH-VALUE EXPLOITS ONLY${RESET}                        ${CYAN}║${RESET}"
echo -e "${CYAN}║${RESET}  Start:  ${GREEN}$(printf '%-50s' "$START_STAGE")${RESET} ${CYAN}║${RESET}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${RESET}"
echo ""

########################################
# TOOL CHECKS
########################################
log "Checking required tools..."
MISSING_TOOLS=()

for t in subfinder assetfinder amass puredns dnsgen httpx nuclei jq; do
  if ! command -v "$t" >/dev/null 2>&1; then
    MISSING_TOOLS+=("$t")
  fi
done

if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
  error "Missing required tools: ${MISSING_TOOLS[*]}"
  exit 1
fi

success "All required tools are installed"

########################################
# PASSIVE
########################################
if should_run passive; then
  stage_header "1/7" "PASSIVE ENUMERATION"

  progress "Running subfinder..."
  subfinder -d "$domain" -silent -all > "$BASE_DIR/passive/subfinder.txt" || true
  echo -e "    ${DIM}Found: ${GREEN}$(wc -l < "$BASE_DIR/passive/subfinder.txt" 2>/dev/null || echo 0)${RESET} ${DIM}domains${RESET}"

  progress "Running assetfinder..."
  assetfinder --subs-only "$domain" > "$BASE_DIR/passive/assetfinder.txt" || true
  echo -e "    ${DIM}Found: ${GREEN}$(wc -l < "$BASE_DIR/passive/assetfinder.txt" 2>/dev/null || echo 0)${RESET} ${DIM}domains${RESET}"

  progress "Running amass (passive)..."
  amass enum -passive -d "$domain" -o "$BASE_DIR/passive/amass.txt" || true
  echo -e "    ${DIM}Found: ${GREEN}$(wc -l < "$BASE_DIR/passive/amass.txt" 2>/dev/null || echo 0)${RESET} ${DIM}domains${RESET}"

  safe_cat "$BASE_DIR/passive/"*.txt | sort -u > "$BASE_DIR/passive/passive_seeds.txt"
  success "Passive enumeration complete: ${BOLD}$(wc -l < "$BASE_DIR/passive/passive_seeds.txt" || echo 0)${RESET} unique domains"
fi

########################################
# BRUTEFORCE
########################################
if should_run bruteforce; then
  stage_header "2/7" "DNS BRUTEFORCE"

  progress "Running puredns bruteforce..."
  puredns bruteforce "$WORDLIST" "$domain" -r "$RESOLVERS" -w "$BASE_DIR/bruteforce/raw.txt" || true

  progress "Resolving and filtering wildcards..."
  puredns resolve "$BASE_DIR/bruteforce/raw.txt" -r "$RESOLVERS" \
    --wildcard-tests 3 -w "$BASE_DIR/bruteforce/resolved.txt" || true

  safe_cat "$BASE_DIR/passive/passive_seeds.txt" \
           "$BASE_DIR/bruteforce/resolved.txt" \
    | sort -u > "$BASE_DIR/final/resolved_fqdns.txt"

  success "Bruteforce complete: ${BOLD}$(wc -l < "$BASE_DIR/final/resolved_fqdns.txt" || echo 0)${RESET} total domains"
fi

########################################
# PERMUTATIONS
########################################
if should_run permutations; then
  stage_header "3/7" "DOMAIN PERMUTATIONS"

  progress "Generating permutations with dnsgen..."
  dnsgen "$BASE_DIR/final/resolved_fqdns.txt" > "$BASE_DIR/permutations/dnsgen_raw.txt" || true

  progress "Filtering in-scope permutations..."
  grep -E "\\.${domain}\$" "$BASE_DIR/permutations/dnsgen_raw.txt" \
    | sort -u > "$BASE_DIR/permutations/all_permutations.txt" || true

  success "Generated ${BOLD}$(wc -l < "$BASE_DIR/permutations/all_permutations.txt" || echo 0)${RESET} permutations"
fi

########################################
# DNS RESOLUTION
########################################
if should_run dns; then
  stage_header "4/7" "DNS RESOLUTION"

  progress "Combining all DNS candidates..."
  safe_cat "$BASE_DIR/final/resolved_fqdns.txt" \
           "$BASE_DIR/permutations/all_permutations.txt" \
    | sort -u > "$BASE_DIR/dns/all_candidates.txt"
  echo -e "    ${DIM}Total candidates: ${YELLOW}$(wc -l < "$BASE_DIR/dns/all_candidates.txt" || echo 0)${RESET}"

  progress "Resolving with puredns (wildcard filtering enabled)..."
  puredns resolve "$BASE_DIR/dns/all_candidates.txt" \
    -r "$RESOLVERS" --wildcard-tests 5 \
    --write-massdns "$BASE_DIR/tmp/puredns.snl" || true

  awk '{print $1}' "$BASE_DIR/tmp/puredns.snl" 2>/dev/null | \
    sed 's/\.$//' | \
    grep -E "\.${domain}\$|^${domain}\$" | \
    sort -u > "$BASE_DIR/dns/resolved_domains.txt" || touch "$BASE_DIR/dns/resolved_domains.txt"

  success "Final resolved domains: ${BOLD}${GREEN}$(wc -l < "$BASE_DIR/dns/resolved_domains.txt" || echo 0)${RESET}"

  progress "Extracting CNAME mappings for reference..."
  grep "CNAME" "$BASE_DIR/tmp/puredns.snl" 2>/dev/null | \
    awk -v domain="$domain" '{
      if ($1 ~ "\\." domain "\\.$" || $1 ~ "^" domain "\\.$") {
        sub(/\.$/, "", $1);
        for(i=2; i<=NF; i++) {
          if($i == "CNAME") {
            target = $(i+1);
            sub(/\.$/, "", target);
            print $1 " → " target;
            break;
          }
        }
      }
    }' > "$BASE_DIR/dns/cname_mappings.txt" || touch "$BASE_DIR/dns/cname_mappings.txt"

  CNAME_COUNT=$(wc -l < "$BASE_DIR/dns/cname_mappings.txt" 2>/dev/null || echo 0)
  [[ $CNAME_COUNT -gt 0 ]] && log "Saved $CNAME_COUNT CNAME mappings to dns/cname_mappings.txt"
fi

########################################
# RECON INTEL (ENHANCED)
########################################
if should_run recon_intel; then
  stage_header "5/7" "RECONNAISSANCE INTELLIGENCE"

  progress "Identifying cloud-hosted assets (comprehensive scan)..."
  
  grep -Eai 'amazonaws|s3-|s3\.|cloudfront\.net|elb\.amazonaws|ec2-|rds\.amazonaws|lambda\.amazonaws|
azure|azurewebsites|cloudapp\.azure|windows\.net|blob\.core|azure-api|trafficmanager|
digitalocean|droplet|
heroku|herokuapp|
github\.io|github\.com/|github\.dev|gitlab\.io|gitlab\.com/|
netlify|vercel|vercel\.app|now\.sh|
firebase|firebaseapp|cloudfunctions\.net|appspot\.com|
cloudflare\.com|cloudflare\.net|workers\.dev|pages\.dev|
fastly|fastly\.net|
akamai|edgekey\.net|edgesuite\.net|
google|gcp|googleapis\.com|appengine|cloud\.google|
cdn\.shopify|myshopify\.com|
wp-engine|wpengine|
pantheon|pantheonsite|
acquia-sites|
webflow\.io|
wix\.com|wixsite\.com|
squarespace\.com|
cargo\.site|
ghost\.io|
zendesk\.com|
hubspot|hubspot\.com|hs-sites\.com|
salesforce|force\.com|visualforce\.com|
intercom|intercom\.io|
discourse\.org|
bynder|getbynder|
bitly|bit\.ly|
rebrandly\.com|
short\.io|
tinyurl\.com|
ow\.ly|
t\.co|
links\.io|
linktr\.ee' \
    "$BASE_DIR/dns/resolved_domains.txt" \
    > "$BASE_DIR/recon_intel/cloud_assets.txt" 2>/dev/null || touch "$BASE_DIR/recon_intel/cloud_assets.txt"
  
  CLOUD_COUNT=$(wc -l < "$BASE_DIR/recon_intel/cloud_assets.txt" 2>/dev/null || echo 0)
  echo -e "    ${DIM}Cloud assets: ${CYAN}${CLOUD_COUNT}${RESET}"
  
  if [[ $CLOUD_COUNT -gt 0 ]]; then
    progress "Categorizing cloud providers..."
    grep -Eai 'amazonaws|s3|cloudfront|elb|ec2|rds|lambda' "$BASE_DIR/recon_intel/cloud_assets.txt" 2>/dev/null | sort -u > "$BASE_DIR/recon_intel/aws_assets.txt" || touch "$BASE_DIR/recon_intel/aws_assets.txt"
    grep -Eai 'azure|azurewebsites|cloudapp|windows\.net|blob\.core' "$BASE_DIR/recon_intel/cloud_assets.txt" 2>/dev/null | sort -u > "$BASE_DIR/recon_intel/azure_assets.txt" || touch "$BASE_DIR/recon_intel/azure_assets.txt"
    grep -Eai 'google|gcp|googleapis|appengine|appspot|cloudfunctions' "$BASE_DIR/recon_intel/cloud_assets.txt" 2>/dev/null | sort -u > "$BASE_DIR/recon_intel/gcp_assets.txt" || touch "$BASE_DIR/recon_intel/gcp_assets.txt"
    grep -Eai 'cloudflare|workers\.dev|pages\.dev' "$BASE_DIR/recon_intel/cloud_assets.txt" 2>/dev/null | sort -u > "$BASE_DIR/recon_intel/cloudflare_assets.txt" || touch "$BASE_DIR/recon_intel/cloudflare_assets.txt"
    grep -Eai 'digitalocean|droplet' "$BASE_DIR/recon_intel/cloud_assets.txt" 2>/dev/null | sort -u > "$BASE_DIR/recon_intel/digitalocean_assets.txt" || touch "$BASE_DIR/recon_intel/digitalocean_assets.txt"
    
    echo -e "    ${DIM}├─ AWS: ${GREEN}$(wc -l < "$BASE_DIR/recon_intel/aws_assets.txt" 2>/dev/null || echo 0)${RESET}"
    echo -e "    ${DIM}├─ Azure: ${GREEN}$(wc -l < "$BASE_DIR/recon_intel/azure_assets.txt" 2>/dev/null || echo 0)${RESET}"
    echo -e "    ${DIM}├─ GCP: ${GREEN}$(wc -l < "$BASE_DIR/recon_intel/gcp_assets.txt" 2>/dev/null || echo 0)${RESET}"
    echo -e "    ${DIM}├─ Cloudflare: ${GREEN}$(wc -l < "$BASE_DIR/recon_intel/cloudflare_assets.txt" 2>/dev/null || echo 0)${RESET}"
    echo -e "    ${DIM}└─ DigitalOcean: ${GREEN}$(wc -l < "$BASE_DIR/recon_intel/digitalocean_assets.txt" 2>/dev/null || echo 0)${RESET}"
  fi

  progress "Detecting potential subdomain takeover candidates (enhanced)..."
  touch "$BASE_DIR/recon_intel/takeover_dns_candidates.txt"
  touch "$BASE_DIR/recon_intel/takeover_mapping.txt"

  if [[ -s "$BASE_DIR/tmp/puredns.snl" ]]; then
    grep -Eai "\.${domain}\. CNAME.*(
azurewebsites\.net|cloudapp\.azure\.com|azure-api\.net|trafficmanager\.net|blob\.core\.windows\.net|
herokuapp\.com|herokussl\.com|
pantheonsite\.io|pantheon\.io|
ghost\.io|
zendesk\.com|
github\.io|github\.com|
gitlab\.io|gitlab\.com|
s3\.amazonaws\.com|s3-website|s3-.*\.amazonaws\.com|
getbynder\.com|
bitly\.com|bit\.ly|
fastly\.net|
shopify\.com|myshopify\.com|
wordpress\.com|
tumblr\.com|
surge\.sh|
cargocollective\.com|
statuspage\.io|
freshdesk\.com|
pingdom\.com|
tilda\.ws|
campaignmonitor\.com|
acquia-sites\.com|
brightcove\.com|
bigcartel\.com|
activehosted\.com|
smugmug\.com|
helpjuice\.com|
helpscout\.net|
desk\.com|
teamwork\.com|
unbounce\.com|
cargo\.site|
statuspage\.io|
uservoice\.com|
getresponse\.com|
vend\.com|
jetbrains\.space|
webflow\.io|
intercom\.help|
kajabi\.com|
thinkific\.com|
teachable\.com|
launchrock\.com|
readme\.io)" \
      "$BASE_DIR/tmp/puredns.snl" 2>/dev/null | \
      awk -v domain="$domain" '{
        if ($1 ~ "\\." domain "\\.$") {
          sub(/\.$/, "", $1);
          for(i=2; i<=NF; i++) {
            if($i ~ /CNAME/) {
              target = $(i+1);
              sub(/\.$/, "", target);
              print $1 " → " target;
              print $1 > "'"$BASE_DIR/recon_intel/takeover_dns_candidates.txt"'"
              break;
            }
          }
        }
      }' > "$BASE_DIR/recon_intel/takeover_mapping.txt" || true
  fi

  {
    cat "$BASE_DIR/recon_intel/cloud_assets.txt" 2>/dev/null
    cat "$BASE_DIR/recon_intel/takeover_dns_candidates.txt" 2>/dev/null
  } | grep -E "\.${domain}$" | sort -u > "$BASE_DIR/recon_intel/takeover_candidates.txt"

  TAKEOVER_COUNT=$(wc -l < "$BASE_DIR/recon_intel/takeover_candidates.txt" 2>/dev/null || echo 0)
  if [[ $TAKEOVER_COUNT -gt 0 ]]; then
    warn "Potential takeover candidates: ${BOLD}${YELLOW}$TAKEOVER_COUNT${RESET}"
    [[ "$VERBOSE" == true ]] && cat "$BASE_DIR/recon_intel/takeover_mapping.txt" | head -10 | sed 's/^/    /'
  else
    success "No obvious takeover candidates detected"
  fi
  
  progress "Analyzing DNS patterns for security insights..."
  grep -E ':[0-9]+' "$BASE_DIR/dns/resolved_domains.txt" 2>/dev/null > "$BASE_DIR/recon_intel/non_standard_ports.txt" || touch "$BASE_DIR/recon_intel/non_standard_ports.txt"
  grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "$BASE_DIR/tmp/puredns.snl" 2>/dev/null | sort -u > "$BASE_DIR/recon_intel/ip_addresses.txt" || touch "$BASE_DIR/recon_intel/ip_addresses.txt"
  
  success "Intelligence gathering complete"
fi

########################################
# HTTP DISCOVERY
########################################
if should_run http_discovery; then
  stage_header "6/7" "HTTP SERVICE DISCOVERY"

  HTTPX_JSON="$BASE_DIR/http_discovery/httpx_full.json"

  DOMAIN_COUNT=$(wc -l < "$BASE_DIR/dns/resolved_domains.txt" || echo 0)
  progress "Probing ${YELLOW}$DOMAIN_COUNT${RESET} domains with httpx..."

  httpx -l "$BASE_DIR/dns/resolved_domains.txt" \
    -threads "$HTTP_THREADS" \
    -rate-limit "$HTTP_RATE" \
    -status-code -title -tech-detect \
    -follow-redirects \
    -json -silent \
    -o "$HTTPX_JSON" || true

  if [[ -s "$HTTPX_JSON" ]]; then
    progress "Processing httpx results..."

    jq -r 'select(.url != null) | .url' "$HTTPX_JSON" 2>/dev/null | sort -u \
      > "$BASE_DIR/http_discovery/live_urls.txt" || touch "$BASE_DIR/http_discovery/live_urls.txt"

    jq -r 'select(.status_code == 200) | .url' "$HTTPX_JSON" 2>/dev/null \
      > "$BASE_DIR/http_discovery/status_200.txt" || touch "$BASE_DIR/http_discovery/status_200.txt"
    jq -r 'select(.status_code == 401) | .url' "$HTTPX_JSON" 2>/dev/null \
      > "$BASE_DIR/http_discovery/status_401.txt" || touch "$BASE_DIR/http_discovery/status_401.txt"
    jq -r 'select(.status_code == 403) | .url' "$HTTPX_JSON" 2>/dev/null \
      > "$BASE_DIR/http_discovery/status_403.txt" || touch "$BASE_DIR/http_discovery/status_403.txt"
    jq -r 'select(.status_code == 404) | .url' "$HTTPX_JSON" 2>/dev/null \
      > "$BASE_DIR/http_discovery/status_404.txt" || touch "$BASE_DIR/http_discovery/status_404.txt"
    jq -r 'select(.status_code >= 500 and .status_code < 600) | .url' "$HTTPX_JSON" 2>/dev/null \
      > "$BASE_DIR/http_discovery/status_5xx.txt" || touch "$BASE_DIR/http_discovery/status_5xx.txt"
    jq -r '.tech[]?' "$HTTPX_JSON" 2>/dev/null | sort -u \
      > "$BASE_DIR/http_discovery/technologies.txt" || touch "$BASE_DIR/http_discovery/technologies.txt"

    success "Live HTTP services: ${BOLD}${GREEN}$(wc -l < "$BASE_DIR/http_discovery/live_urls.txt" || echo 0)${RESET}"
    echo -e "    ${DIM}200 OK: ${GREEN}$(wc -l < "$BASE_DIR/http_discovery/status_200.txt" 2>/dev/null || echo 0)${RESET} ${DIM}| 401: ${YELLOW}$(wc -l < "$BASE_DIR/http_discovery/status_401.txt" 2>/dev/null || echo 0)${RESET} ${DIM}| 403: ${YELLOW}$(wc -l < "$BASE_DIR/http_discovery/status_403.txt" 2>/dev/null || echo 0)${RESET}${RESET}"
  else
    warn "No httpx output generated"
    touch "$BASE_DIR/http_discovery/live_urls.txt"
  fi
fi

########################################
# NUCLEI SCAN (AGGRESSIVE - MEDIUM+ ONLY)
########################################
if should_run nuclei; then
  stage_header "7/7" "AGGRESSIVE VULNERABILITY SCANNING (MEDIUM+ ONLY)"

  run_nuclei_scan() {
    local target_file="$1"
    local templates="$2"
    local severity="$3"
    local output_file="$4"
    local description="$5"
    local exclude_tags="${6:-dos,fuzz,intrusive,headless,generic,token}"
    mkdir -p "$(dirname "$output_file")"

    if [[ ! -f "$target_file" ]] || [[ ! -s "$target_file" ]]; then
      log "Skip ${description}: No targets"
      return
    fi

    local count
    count=$(wc -l < "$target_file")
    
    # INTELLIGENT CONCURRENCY CALCULATION
    # Rule: concurrency must be <= max-host-error to avoid warnings
    # Also scale down for small target sets
    local concurrency
    local max_host_error
    local rate_limit
    
    if [[ $count -le 50 ]]; then
      # Small target set: conservative settings
      concurrency=10
      max_host_error=20
      rate_limit=150
    elif [[ $count -le 150 ]]; then
      # Medium target set: moderate settings
      concurrency=20
      max_host_error=30
      rate_limit=200
    elif [[ $count -le 500 ]]; then
      # Large target set: balanced settings
      concurrency=30
      max_host_error=40
      rate_limit=250
    else
      # Very large target set: aggressive but safe
      concurrency=40
      max_host_error=50
      rate_limit=300
    fi
    
    # Safety check: ensure concurrency <= max_host_error
    if [[ $concurrency -gt $max_host_error ]]; then
      concurrency=$max_host_error
    fi
    
    progress "${CYAN}${description}${RESET} (${count} targets, concurrency: ${concurrency})"

    nuclei -l "$target_file" -t "$templates" -severity "$severity" -et "$exclude_tags" \
      -o "$output_file" -json-export "${output_file}.json" -silent \
      -timeout "$NUCLEI_TIMEOUT" -retries 1 \
      -rate-limit "$rate_limit" \
      -bulk-size 25 \
      -concurrency "$concurrency" \
      -max-host-error "$max_host_error" \
      -follow-host-redirects \
      -disable-update-check 2>"${output_file}_error.log" || true

    local results
    results=$(wc -l < "$output_file" 2>/dev/null || echo 0)
    if [[ $results -gt 0 ]]; then
      success "${description}: ${GREEN}${results}${RESET} findings"
    else
      log "${description}: No findings"
    fi
  }

  # Prepare EXPLOIT-FOCUSED targets only
  if [[ -f "$BASE_DIR/http_discovery/live_urls.txt" ]] && [[ -s "$BASE_DIR/http_discovery/live_urls.txt" ]]; then
    progress "Building exploit-focused target list..."
    
    {
      cat "$BASE_DIR/http_discovery/live_urls.txt"
      
      # Add CRITICAL exploit endpoints for 200 OK hosts
      if [[ -s "$BASE_DIR/http_discovery/status_200.txt" ]]; then
        while IFS= read -r url; do
          base=$(echo "$url" | sed 's/\/$//')
          for path in \
            /.env /.env.production /.env.local /.env.development \
            /.git/config /.git/HEAD /.git/index \
            /.aws/credentials /.aws/config \
            /config.json /config.yml /config.yaml /configuration.yml \
            /.htpasswd /web.config /WEB-INF/web.xml \
            /server-status /server-info \
            /actuator/env /actuator/heapdump /actuator/mappings /actuator/metrics \
            /swagger.json /swagger-ui.html /api-docs /openapi.json \
            /graphql /graphiql \
            /debug/pprof /debug/vars /_profiler \
            /.dockerenv /Dockerfile /docker-compose.yml; do
            echo "$base$path"
          done
        done < "$BASE_DIR/http_discovery/status_200.txt"
      fi
    } | sort -u > "$BASE_DIR/nuclei/scan_targets.txt"
    
    success "Prepared: $(wc -l < "$BASE_DIR/nuclei/scan_targets.txt") exploit-focused targets"
  else
    touch "$BASE_DIR/nuclei/scan_targets.txt"
    warn "No live URLs found, skipping nuclei scan"
    exit 0
  fi

  # =================================================================
  # PHASE 1: CRITICAL EXPOSURES (File Leaks, Configs, Secrets)
  # =================================================================
  progress "Phase 1: Critical File Exposures & Secrets"
  
  run_nuclei_scan "$BASE_DIR/nuclei/scan_targets.txt" \
    "$NUCLEI_TEMPLATES/http/exposures/" \
    "medium,high,critical" "$BASE_DIR/nuclei/raw/01_exposures.txt" "Critical Exposures" "dos,fuzz,token"

  # =================================================================
  # PHASE 2: AUTHENTICATION ISSUES
  # =================================================================
  progress "Phase 2: Authentication Bypasses & Default Credentials"
  
  run_nuclei_scan "$BASE_DIR/nuclei/scan_targets.txt" \
    "$NUCLEI_TEMPLATES/http/default-logins/" \
    "medium,high,critical" "$BASE_DIR/nuclei/raw/02_default_creds.txt" "Default Credentials" "dos,fuzz"

  # =================================================================
  # PHASE 3: INJECTION VULNERABILITIES (SQLi, Command Injection, XXE)
  # =================================================================
  progress "Phase 3: Injection Vulnerabilities (HIGH+ only)"
  
  run_nuclei_scan "$BASE_DIR/nuclei/scan_targets.txt" \
    "$NUCLEI_TEMPLATES/http/vulnerabilities/generic/" \
    "high,critical" "$BASE_DIR/nuclei/raw/03_injections.txt" "Injection Attacks" "dos,fuzz,headless"

  # =================================================================
  # PHASE 4: RECENT CRITICAL CVEs (2024-2025)
  # =================================================================
  progress "Phase 4: Recent Critical CVEs (2024-2025)"
  
  run_nuclei_scan "$BASE_DIR/nuclei/scan_targets.txt" \
    "$NUCLEI_TEMPLATES/http/cves/2024/,$NUCLEI_TEMPLATES/http/cves/2025/" \
    "high,critical" "$BASE_DIR/nuclei/raw/04_recent_cves.txt" "Recent CVEs" "dos,fuzz"

  # =================================================================
  # PHASE 5: ALL CRITICAL CVEs
  # =================================================================
  progress "Phase 5: All Critical CVEs (Any Year)"
  
  run_nuclei_scan "$BASE_DIR/nuclei/scan_targets.txt" \
    "$NUCLEI_TEMPLATES/http/cves/" \
    "critical" "$BASE_DIR/nuclei/raw/05_all_critical_cves.txt" "All Critical CVEs" "dos,fuzz,headless,intrusive"

  # =================================================================
  # PHASE 6: SUBDOMAIN TAKEOVER (If candidates exist)
  # =================================================================
  if [[ -s "$BASE_DIR/recon_intel/takeover_candidates.txt" ]]; then
    progress "Phase 6: Subdomain Takeover Detection"
    run_nuclei_scan "$BASE_DIR/recon_intel/takeover_candidates.txt" \
      "$NUCLEI_TEMPLATES/http/takeovers/,$NUCLEI_TEMPLATES/dns/" \
      "medium,high,critical" "$BASE_DIR/nuclei/raw/06_takeover.txt" "Subdomain Takeover" "dos"
  fi

  # =================================================================
  # PHASE 7: TECHNOLOGY-SPECIFIC EXPLOITS (HIGH+ only)
  # =================================================================
  progress "Phase 7: Technology-Specific Exploits"
  
  if [[ -s "$BASE_DIR/http_discovery/technologies.txt" ]]; then
    TECH_FOUND=false
    
    # WordPress
    if grep -qi "wordpress" "$BASE_DIR/http_discovery/technologies.txt" 2>/dev/null; then
      TECH_FOUND=true
      grep -i "wordpress" "$BASE_DIR/http_discovery/live_urls.txt" 2>/dev/null > "$BASE_DIR/nuclei/wordpress_targets.txt" || touch "$BASE_DIR/nuclei/wordpress_targets.txt"
      [[ -s "$BASE_DIR/nuclei/wordpress_targets.txt" ]] && \
        run_nuclei_scan "$BASE_DIR/nuclei/wordpress_targets.txt" \
          "$NUCLEI_TEMPLATES/http/vulnerabilities/wordpress/" \
          "high,critical" "$BASE_DIR/nuclei/raw/07_wordpress.txt" "WordPress Exploits" "dos,fuzz"
    fi

    # Jenkins
    if grep -qi "jenkins" "$BASE_DIR/http_discovery/technologies.txt" 2>/dev/null; then
      TECH_FOUND=true
      grep -i "jenkins" "$BASE_DIR/http_discovery/live_urls.txt" 2>/dev/null > "$BASE_DIR/nuclei/jenkins_targets.txt" || touch "$BASE_DIR/nuclei/jenkins_targets.txt"
      [[ -s "$BASE_DIR/nuclei/jenkins_targets.txt" ]] && \
        run_nuclei_scan "$BASE_DIR/nuclei/jenkins_targets.txt" \
          "$NUCLEI_TEMPLATES/http/vulnerabilities/jenkins/" \
          "high,critical" "$BASE_DIR/nuclei/raw/07_jenkins.txt" "Jenkins RCE" "dos,fuzz"
    fi

    # Jira/Atlassian
    if grep -qi "jira\|confluence\|atlassian" "$BASE_DIR/http_discovery/technologies.txt" 2>/dev/null; then
      TECH_FOUND=true
      grep -Ei "jira|confluence|atlassian" "$BASE_DIR/http_discovery/live_urls.txt" 2>/dev/null > "$BASE_DIR/nuclei/atlassian_targets.txt" || touch "$BASE_DIR/nuclei/atlassian_targets.txt"
      [[ -s "$BASE_DIR/nuclei/atlassian_targets.txt" ]] && \
        run_nuclei_scan "$BASE_DIR/nuclei/atlassian_targets.txt" \
          "$NUCLEI_TEMPLATES/http/vulnerabilities/atlassian/" \
          "high,critical" "$BASE_DIR/nuclei/raw/07_atlassian.txt" "Atlassian Exploits" "dos,fuzz"
    fi
    
    # Spring Boot
    if grep -qi "spring\|java" "$BASE_DIR/http_discovery/technologies.txt" 2>/dev/null; then
      TECH_FOUND=true
      run_nuclei_scan "$BASE_DIR/nuclei/scan_targets.txt" \
        "$NUCLEI_TEMPLATES/http/vulnerabilities/springboot/,$NUCLEI_TEMPLATES/http/misconfiguration/springboot/" \
        "high,critical" "$BASE_DIR/nuclei/raw/07_springboot.txt" "Spring Boot RCE" "dos,fuzz"
    fi

    # Apache/Struts
    if grep -qi "struts\|apache" "$BASE_DIR/http_discovery/technologies.txt" 2>/dev/null; then
      TECH_FOUND=true
      run_nuclei_scan "$BASE_DIR/nuclei/scan_targets.txt" \
        "$NUCLEI_TEMPLATES/http/vulnerabilities/apache/" \
        "high,critical" "$BASE_DIR/nuclei/raw/07_apache.txt" "Apache/Struts RCE" "dos,fuzz"
    fi
    
    [[ "$TECH_FOUND" == false ]] && log "No exploitable technologies detected"
  fi

  # =================================================================
  # PHASE 8: DANGEROUS MISCONFIGURATIONS (HIGH+ only)
  # =================================================================
  progress "Phase 8: RCE-Enabling Misconfigurations"
  
  run_nuclei_scan "$BASE_DIR/nuclei/scan_targets.txt" \
    "$NUCLEI_TEMPLATES/http/misconfiguration/" \
    "high,critical" "$BASE_DIR/nuclei/raw/08_misconfigs.txt" "Dangerous Misconfigs" "dos,fuzz,headless,generic,token"

  # =================================================================
  # PHASE 9: COMPREHENSIVE VULNERABILITY SCAN (Adaptive)
  # =================================================================
  progress "Phase 9: Comprehensive Scan (Adaptive Strategy)"
  TARGET_COUNT=$(wc -l < "$BASE_DIR/nuclei/scan_targets.txt" 2>/dev/null || echo 0)
  echo -e "    ${DIM}Target count: ${YELLOW}$TARGET_COUNT${RESET}"

  if [[ $TARGET_COUNT -le 150 ]]; then
    progress "Small scope ($TARGET_COUNT targets) - MEDIUM+ full scan"
    run_nuclei_scan "$BASE_DIR/nuclei/scan_targets.txt" \
      "$NUCLEI_TEMPLATES/http/vulnerabilities/" \
      "medium,high,critical" "$BASE_DIR/nuclei/raw/09_comprehensive.txt" \
      "All Vulnerabilities (MEDIUM+)" "dos,fuzz,intrusive,headless"
  elif [[ $TARGET_COUNT -le 500 ]]; then
    progress "Medium scope ($TARGET_COUNT targets) - HIGH+ focused"
    run_nuclei_scan "$BASE_DIR/nuclei/scan_targets.txt" \
      "$NUCLEI_TEMPLATES/http/vulnerabilities/" \
      "high,critical" "$BASE_DIR/nuclei/raw/09_comprehensive.txt" \
      "High-Impact Vulnerabilities" "dos,fuzz,intrusive,headless"
  else
    progress "Large scope ($TARGET_COUNT targets) - CRITICAL only"
    run_nuclei_scan "$BASE_DIR/nuclei/scan_targets.txt" \
      "$NUCLEI_TEMPLATES/http/vulnerabilities/" \
      "critical" "$BASE_DIR/nuclei/raw/09_comprehensive.txt" \
      "Critical Vulnerabilities" "dos,fuzz,intrusive,headless"
  fi

  # =================================================================
  # PHASE 10: CUSTOM TEMPLATES
  # =================================================================
  if [[ -d "$CUSTOM_NUCLEI_TEMPLATES" ]] && [[ -n "$(ls -A "$CUSTOM_NUCLEI_TEMPLATES" 2>/dev/null)" ]]; then
    progress "Phase 10: Custom Templates"
    run_nuclei_scan "$BASE_DIR/nuclei/scan_targets.txt" \
      "$CUSTOM_NUCLEI_TEMPLATES/" \
      "medium,high,critical" "$BASE_DIR/nuclei/raw/10_custom.txt" "Custom Exploits" "dos"
  fi

  # =================================================================
  # AGGRESSIVE NOISE FILTERING
  # =================================================================
  progress "Filtering results (AGGRESSIVE - removing ALL noise)..."
  
  cat "$BASE_DIR/nuclei/raw/"*.txt 2>/dev/null | sort -u > "$BASE_DIR/nuclei/processed/all_findings_raw.txt" || touch "$BASE_DIR/nuclei/processed/all_findings_raw.txt"
  
  # Remove info, low, unknown AND common false positives
  grep -Ev '\[info\]|\[low\]|\[unknown\]' "$BASE_DIR/nuclei/processed/all_findings_raw.txt" 2>/dev/null | \
    grep -Ev 'dns-saas|tech-detect|waf-detect|fingerprint|ssl-|tls-|http-trace|options-method|
missing-security-headers|x-frame-options|x-content-type|content-security-policy|strict-transport|
permissions-policy|referrer-policy|x-permitted|x-xss-protection|
weak-cipher|deprecated-tls|self-signed|untrusted-root|
robots-txt|sitemap|security\.txt|humans\.txt|ads\.txt|
cookie-without-secure|cookie-without-httponly|
verbose-|exposed-panel|login-page|signup-page|
error-based|version-detect|default-page|generic-detect|
detect-|discovery-|service-detect|application-detect' 2>/dev/null | \
    sort -u > "$BASE_DIR/nuclei/processed/all_findings.txt" || touch "$BASE_DIR/nuclei/processed/all_findings.txt"
  
  # Categorize by severity
  grep -Ei '\[critical\]' "$BASE_DIR/nuclei/processed/all_findings.txt" 2>/dev/null | sort -u > "$BASE_DIR/nuclei/processed/CRITICAL.txt" || touch "$BASE_DIR/nuclei/processed/CRITICAL.txt"
  grep -Ei '\[high\]' "$BASE_DIR/nuclei/processed/all_findings.txt" 2>/dev/null | sort -u > "$BASE_DIR/nuclei/processed/HIGH.txt" || touch "$BASE_DIR/nuclei/processed/HIGH.txt"
  grep -Ei '\[medium\]' "$BASE_DIR/nuclei/processed/all_findings.txt" 2>/dev/null | sort -u > "$BASE_DIR/nuclei/processed/MEDIUM.txt" || touch "$BASE_DIR/nuclei/processed/MEDIUM.txt"

  # Filter JSON (remove info/low/unknown)
  if ls "$BASE_DIR/nuclei/json/"*.json 1> /dev/null 2>&1; then
    jq -s 'add | map(select(.info.severity != "info" and .info.severity != "low" and .info.severity != "unknown"))' \
      "$BASE_DIR/nuclei/json/"*.json 2>/dev/null > "$BASE_DIR/nuclei/processed/all_findings.json" || echo "[]" > "$BASE_DIR/nuclei/processed/all_findings.json"
  else
    echo "[]" > "$BASE_DIR/nuclei/processed/all_findings.json"
  fi

  # Generate summary
  CRIT=$(wc -l < "$BASE_DIR/nuclei/processed/CRITICAL.txt" 2>/dev/null || echo 0)
  HIGH=$(wc -l < "$BASE_DIR/nuclei/processed/HIGH.txt" 2>/dev/null || echo 0)
  MED=$(wc -l < "$BASE_DIR/nuclei/processed/MEDIUM.txt" 2>/dev/null || echo 0)
  ALL=$(wc -l < "$BASE_DIR/nuclei/processed/all_findings.txt" 2>/dev/null || echo 0)

  {
    echo "================================================================="
    echo "AGGRESSIVE NUCLEI SCAN SUMMARY - $(date)"
    echo "================================================================="
    echo ""
    echo "EXPLOITABLE VULNERABILITIES FOUND:"
    echo "  🔴 Critical:  $CRIT"
    echo "  🟠 High:      $HIGH"
    echo "  🟡 Medium:    $MED"
    echo "  ━━━━━━━━━━━━━━━━━━━"
    echo "  ✅ Total:     $ALL"
    echo ""
    echo "FILTERING APPLIED:"
    echo "  ✗ Removed: info, low, unknown severity"
    echo "  ✗ Removed: fingerprinting, tech detection"
    echo "  ✗ Removed: SSL/TLS info, missing headers"
    echo "  ✗ Removed: generic detections, exposed panels"
    echo ""
    echo "================================================================="
    
    if [[ $CRIT -gt 0 ]]; then
      echo ""
      echo "🔴 CRITICAL FINDINGS (IMMEDIATE ACTION REQUIRED):"
      echo "================================================================="
      head -50 "$BASE_DIR/nuclei/processed/CRITICAL.txt"
      [[ $CRIT -gt 50 ]] && echo "... and $((CRIT - 50)) more (see nuclei/processed/CRITICAL.txt)"
    fi
    
    if [[ $HIGH -gt 0 ]]; then
      echo ""
      echo "🟠 HIGH SEVERITY FINDINGS:"
      echo "================================================================="
      head -30 "$BASE_DIR/nuclei/processed/HIGH.txt"
      [[ $HIGH -gt 30 ]] && echo "... and $((HIGH - 30)) more (see nuclei/processed/HIGH.txt)"
    fi
    
    if [[ $MED -gt 0 ]]; then
      echo ""
      echo "🟡 MEDIUM SEVERITY FINDINGS:"
      echo "================================================================="
      head -20 "$BASE_DIR/nuclei/processed/MEDIUM.txt"
      [[ $MED -gt 20 ]] && echo "... and $((MED - 20)) more (see nuclei/processed/MEDIUM.txt)"
    fi
    
    if [[ $ALL -eq 0 ]]; then
      echo ""
      echo "✅ NO EXPLOITABLE VULNERABILITIES DETECTED"
      echo "   (All info/low findings filtered out)"
    fi
  } > "$BASE_DIR/nuclei/SCAN_SUMMARY.txt"

  # Display results
  echo ""
  if [[ $CRIT -gt 0 ]]; then
    warn "🔴 CRITICAL: ${RED}${BOLD}$CRIT${RESET} exploitable vulnerabilities"
  fi
  if [[ $HIGH -gt 0 ]]; then
    warn "🟠 HIGH: ${YELLOW}${BOLD}$HIGH${RESET} high-severity issues"
  fi
  if [[ $MED -gt 0 ]]; then
    log "🟡 MEDIUM: ${CYAN}$MED${RESET} medium-severity issues"
  fi
  if [[ $ALL -gt 0 ]]; then
    success "✓ Total EXPLOITABLE findings: ${GREEN}${BOLD}$ALL${RESET} (info/low filtered)"
  else
    success "✓ No exploitable vulnerabilities detected (info/low filtered)"
  fi

  cp "$BASE_DIR/nuclei/processed/CRITICAL.txt" "$BASE_DIR/nuclei/CRITICAL_FINDINGS.txt" 2>/dev/null || true
  cp "$BASE_DIR/nuclei/processed/HIGH.txt" "$BASE_DIR/nuclei/HIGH_FINDINGS.txt" 2>/dev/null || true
fi

########################################
# FINAL SUMMARY
########################################
echo ""
echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║${RESET}          ${BOLD}${GREEN}AGGRESSIVE RECONNAISSANCE COMPLETE${RESET}             ${CYAN}║${RESET}"
echo -e "${CYAN}╠════════════════════════════════════════════════════════════════╣${RESET}"
echo -e "${CYAN}║${RESET}  Target: ${YELLOW}${BOLD}$(printf '%-50s' "$domain")${RESET} ${CYAN}║${RESET}"
echo -e "${CYAN}╠════════════════════════════════════════════════════════════════╣${RESET}"
echo -e "${CYAN}║${RESET}  ${BOLD}Discovery Statistics${RESET}                                    ${CYAN}║${RESET}"
echo -e "${CYAN}║${RESET}  ├─ Domains Found:      ${GREEN}$(printf '%6s' "$(wc -l < "$BASE_DIR/dns/resolved_domains.txt" 2>/dev/null || echo 0)")${RESET}                         ${CYAN}║${RESET}"
echo -e "${CYAN}║${RESET}  ├─ Live HTTP:          ${GREEN}$(printf '%6s' "$(wc -l < "$BASE_DIR/http_discovery/live_urls.txt" 2>/dev/null || echo 0)")${RESET}                         ${CYAN}║${RESET}"
echo -e "${CYAN}║${RESET}  ├─ Status 200:         ${GREEN}$(printf '%6s' "$(wc -l < "$BASE_DIR/http_discovery/status_200.txt" 2>/dev/null || echo 0)")${RESET}                         ${CYAN}║${RESET}"
echo -e "${CYAN}║${RESET}  ├─ Status 401:         ${YELLOW}$(printf '%6s' "$(wc -l < "$BASE_DIR/http_discovery/status_401.txt" 2>/dev/null || echo 0)")${RESET}                         ${CYAN}║${RESET}"
echo -e "${CYAN}║${RESET}  └─ Status 403:         ${YELLOW}$(printf '%6s' "$(wc -l < "$BASE_DIR/http_discovery/status_403.txt" 2>/dev/null || echo 0)")${RESET}                         ${CYAN}║${RESET}"
echo -e "${CYAN}║${RESET}                                                                ${CYAN}║${RESET}"
echo -e "${CYAN}║${RESET}  ${BOLD}Security Intelligence${RESET}                                   ${CYAN}║${RESET}"
echo -e "${CYAN}║${RESET}  ├─ Cloud Assets:       ${CYAN}$(printf '%6s' "$(wc -l < "$BASE_DIR/recon_intel/cloud_assets.txt" 2>/dev/null || echo 0)")${RESET}                         ${CYAN}║${RESET}"
echo -e "${CYAN}║${RESET}  ├─ AWS:                ${GREEN}$(printf '%6s' "$(wc -l < "$BASE_DIR/recon_intel/aws_assets.txt" 2>/dev/null || echo 0)")${RESET}                         ${CYAN}║${RESET}"
echo -e "${CYAN}║${RESET}  ├─ Azure:              ${GREEN}$(printf '%6s' "$(wc -l < "$BASE_DIR/recon_intel/azure_assets.txt" 2>/dev/null || echo 0)")${RESET}                         ${CYAN}║${RESET}"
echo -e "${CYAN}║${RESET}  ├─ GCP:                ${GREEN}$(printf '%6s' "$(wc -l < "$BASE_DIR/recon_intel/gcp_assets.txt" 2>/dev/null || echo 0)")${RESET}                         ${CYAN}║${RESET}"
echo -e "${CYAN}║${RESET}  ├─ Takeover Risks:     ${YELLOW}$(printf '%6s' "$(wc -l < "$BASE_DIR/recon_intel/takeover_candidates.txt" 2>/dev/null || echo 0)")${RESET}                         ${CYAN}║${RESET}"
echo -e "${CYAN}║${RESET}  ├─ Critical Findings:  ${RED}$(printf '%6s' "$(wc -l < "$BASE_DIR/nuclei/CRITICAL_FINDINGS.txt" 2>/dev/null || echo 0)")${RESET}                         ${CYAN}║${RESET}"
echo -e "${CYAN}║${RESET}  └─ High Findings:      ${YELLOW}$(printf '%6s' "$(wc -l < "$BASE_DIR/nuclei/HIGH_FINDINGS.txt" 2>/dev/null || echo 0)")${RESET}                         ${CYAN}║${RESET}"
echo -e "${CYAN}╠════════════════════════════════════════════════════════════════╣${RESET}"
echo -e "${CYAN}║${RESET}  ${BOLD}Output Location${RESET}                                         ${CYAN}║${RESET}"
echo -e "${CYAN}║${RESET}  ${DIM}$(printf '%-60s' "$BASE_DIR")${RESET}  ${CYAN}║${RESET}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${RESET}"

# Generate report
{
  echo "╔════════════════════════════════════════════════════════════════╗"
  echo "║   AGGRESSIVE RECONNAISSANCE REPORT - $domain"
  echo "║   Generated: $(date '+%F %T')"
  echo "║   Mode: MEDIUM+ EXPLOITABLE VULNERABILITIES ONLY"
  echo "╚════════════════════════════════════════════════════════════════╝"
  echo ""
  echo "═══ DISCOVERY STATISTICS ═══"
  echo ""
  echo "Enumeration Results:"
  echo "  • Total Domains:     $(wc -l < "$BASE_DIR/dns/resolved_domains.txt" 2>/dev/null || echo 0)"
  echo "  • Live HTTP:         $(wc -l < "$BASE_DIR/http_discovery/live_urls.txt" 2>/dev/null || echo 0)"
  echo "  • Technologies:      $(wc -l < "$BASE_DIR/http_discovery/technologies.txt" 2>/dev/null || echo 0)"
  echo ""
  echo "HTTP Status:"
  echo "  • 200 OK:            $(wc -l < "$BASE_DIR/http_discovery/status_200.txt" 2>/dev/null || echo 0)"
  echo "  • 401 Unauthorized:  $(wc -l < "$BASE_DIR/http_discovery/status_401.txt" 2>/dev/null || echo 0)"
  echo "  • 403 Forbidden:     $(wc -l < "$BASE_DIR/http_discovery/status_403.txt" 2>/dev/null || echo 0)"
  echo "  • 5xx Errors:        $(wc -l < "$BASE_DIR/http_discovery/status_5xx.txt" 2>/dev/null || echo 0)"
  echo ""
  echo "═══ EXPLOITABLE VULNERABILITIES (MEDIUM+) ═══"
  echo ""
  CRIT_COUNT=$(wc -l < "$BASE_DIR/nuclei/CRITICAL_FINDINGS.txt" 2>/dev/null || echo 0)
  HIGH_COUNT=$(wc -l < "$BASE_DIR/nuclei/HIGH_FINDINGS.txt" 2>/dev/null || echo 0)
  MED_COUNT=$(wc -l < "$BASE_DIR/nuclei/processed/MEDIUM.txt" 2>/dev/null || echo 0)
  echo "🔴 Critical: $CRIT_COUNT"
  echo "🟠 High:     $HIGH_COUNT"
  echo "🟡 Medium:   $MED_COUNT"
  echo ""
  if [[ $CRIT_COUNT -gt 0 ]]; then
    echo "Critical Findings:"
    head -30 "$BASE_DIR/nuclei/CRITICAL_FINDINGS.txt" 2>/dev/null | sed 's/^/  • /'
    [[ $CRIT_COUNT -gt 30 ]] && echo "  ... and $((CRIT_COUNT - 30)) more"
  fi
  echo ""
  if [[ $HIGH_COUNT -gt 0 ]]; then
    echo "High Severity Findings:"
    head -20 "$BASE_DIR/nuclei/HIGH_FINDINGS.txt" 2>/dev/null | sed 's/^/  • /'
    [[ $HIGH_COUNT -gt 20 ]] && echo "  ... and $((HIGH_COUNT - 20)) more"
  fi
  echo ""
  echo "═══ CLOUD INFRASTRUCTURE ═══"
  echo ""
  CLOUD_COUNT=$(wc -l < "$BASE_DIR/recon_intel/cloud_assets.txt" 2>/dev/null || echo 0)
  AWS_COUNT=$(wc -l < "$BASE_DIR/recon_intel/aws_assets.txt" 2>/dev/null || echo 0)
  AZURE_COUNT=$(wc -l < "$BASE_DIR/recon_intel/azure_assets.txt" 2>/dev/null || echo 0)
  GCP_COUNT=$(wc -l < "$BASE_DIR/recon_intel/gcp_assets.txt" 2>/dev/null || echo 0)
  echo "Cloud Assets: $CLOUD_COUNT"
  echo "  ├─ AWS:    $AWS_COUNT"
  echo "  ├─ Azure:  $AZURE_COUNT"
  echo "  └─ GCP:    $GCP_COUNT"
  echo ""
  TAKEOVER_COUNT=$(wc -l < "$BASE_DIR/recon_intel/takeover_candidates.txt" 2>/dev/null || echo 0)
  echo "Subdomain Takeover Candidates: $TAKEOVER_COUNT"
  if [[ $TAKEOVER_COUNT -gt 0 ]]; then
    echo ""
    head -15 "$BASE_DIR/recon_intel/takeover_candidates.txt" 2>/dev/null | sed 's/^/  • /'
  fi
  echo ""
  echo "═══ FILE LOCATIONS ═══"
  echo ""
  echo "Results:           $BASE_DIR"
  echo "Critical Findings: $BASE_DIR/nuclei/CRITICAL_FINDINGS.txt"
  echo "High Findings:     $BASE_DIR/nuclei/HIGH_FINDINGS.txt"
  echo "Scan Summary:      $BASE_DIR/nuclei/SCAN_SUMMARY.txt"
  echo ""
  echo "╔════════════════════════════════════════════════════════════════╗"
  echo "║  Report Complete - $(date '+%F %T')"
  echo "╚════════════════════════════════════════════════════════════════╝"
} > "$BASE_DIR/FINAL_REPORT.txt"

echo ""
success "Final report: ${CYAN}$BASE_DIR/FINAL_REPORT.txt${RESET}"
echo ""

if [[ "$VERBOSE" == true ]]; then
  cat "$BASE_DIR/FINAL_REPORT.txt"
fi
