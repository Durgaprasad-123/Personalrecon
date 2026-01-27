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
  echo -e "${BOLD}  Automated Reconnaissance Script${RESET}"
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
  echo -e "  ${CYAN}http_exploitation${RESET}  High-value target identification"
  echo -e "  ${CYAN}nuclei${RESET}             Vulnerability scanning"
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
STAGES=(passive bruteforce permutations dns recon_intel http_discovery http_exploitation nuclei)

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
NUCLEI_CONCURRENCY=30
NUCLEI_RATE=200
NUCLEI_TIMEOUT=10

RESOLVERS="$HOME/resolvers.txt"
WORDLIST="$HOME/wordlists/dns.txt"
NUCLEI_TEMPLATES="$HOME/nuclei-templates"
CUSTOM_NUCLEI_TEMPLATES="$HOME/custom-nuclei-templates"

OUTPUT_ROOT="${OUTPUT_ROOT:-$PROJECT_ROOT/output}"
BASE_DIR="$OUTPUT_ROOT/$domain"

mkdir -p "$BASE_DIR"/{passive,bruteforce,permutations,dns,final,tmp,logs,recon_intel,http_discovery,http_exploitation,nuclei/{raw,processed,json}}

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
echo -e "${CYAN}║${RESET}          ${BOLD}${GREEN}AUTOMATED RECONNAISSANCE FRAMEWORK${RESET}                ${CYAN}║${RESET}"
echo -e "${CYAN}╠════════════════════════════════════════════════════════════╣${RESET}"
echo -e "${CYAN}║${RESET}  Target: ${YELLOW}${BOLD}$(printf '%-50s' "$domain")${RESET} ${CYAN}║${RESET}"
echo -e "${CYAN}║${RESET}  Output: ${DIM}$(printf '%-50s' "$BASE_DIR")${RESET} ${CYAN}║${RESET}"
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
  stage_header "1/8" "PASSIVE ENUMERATION"

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
  stage_header "2/8" "DNS BRUTEFORCE"

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
  stage_header "3/8" "DOMAIN PERMUTATIONS"

  progress "Generating permutations with dnsgen..."
  dnsgen "$BASE_DIR/final/resolved_fqdns.txt" > "$BASE_DIR/permutations/dnsgen_raw.txt" || true

  progress "Filtering in-scope permutations..."
  grep -E "\\.${domain}\$" "$BASE_DIR/permutations/dnsgen_raw.txt" \
    | sort -u > "$BASE_DIR/permutations/all_permutations.txt" || true

  success "Generated ${BOLD}$(wc -l < "$BASE_DIR/permutations/all_permutations.txt" || echo 0)${RESET} permutations"
fi

########################################
# DNS
########################################
if should_run dns; then
  stage_header "4/8" "DNS RESOLUTION"

  progress "Combining all DNS candidates..."
  safe_cat "$BASE_DIR/final/resolved_fqdns.txt" \
           "$BASE_DIR/permutations/all_permutations.txt" \
    | sort -u > "$BASE_DIR/dns/all_candidates.txt"
  echo -e "    ${DIM}Total candidates: ${YELLOW}$(wc -l < "$BASE_DIR/dns/all_candidates.txt" || echo 0)${RESET}"

  progress "Resolving with puredns (wildcard filtering enabled)..."
  puredns resolve "$BASE_DIR/dns/all_candidates.txt" \
    -r "$RESOLVERS" --wildcard-tests 5 \
    --write-massdns "$BASE_DIR/tmp/puredns.snl" || true

  # FIX: Extract domains from massdns output AND filter to only your target domain
  awk '{print $1}' "$BASE_DIR/tmp/puredns.snl" 2>/dev/null | \
    sed 's/\.$//' | \
    grep -E "\.${domain}\$|^${domain}\$" | \
    sort -u > "$BASE_DIR/dns/resolved_domains.txt" || touch "$BASE_DIR/dns/resolved_domains.txt"

  success "Final resolved domains: ${BOLD}${GREEN}$(wc -l < "$BASE_DIR/dns/resolved_domains.txt" || echo 0)${RESET}"
  
  # Optional: Save CNAME mappings for reference (without adding CNAMEs to resolved list)
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
# RECON INTEL
########################################
if should_run recon_intel; then
  stage_header "5/8" "RECONNAISSANCE INTELLIGENCE"

  progress "Identifying cloud-hosted assets..."
  grep -Eai 'amazonaws|s3|azure|cloudfront|cloudflare|fastly|google' \
    "$BASE_DIR/dns/resolved_domains.txt" \
    > "$BASE_DIR/recon_intel/cloud_assets.txt" 2>/dev/null || touch "$BASE_DIR/recon_intel/cloud_assets.txt"
  echo -e "    ${DIM}Cloud assets: ${CYAN}$(wc -l < "$BASE_DIR/recon_intel/cloud_assets.txt" 2>/dev/null || echo 0)${RESET}"

  progress "Detecting potential subdomain takeover candidates..."
  touch "$BASE_DIR/recon_intel/takeover_dns_candidates.txt"
  touch "$BASE_DIR/recon_intel/takeover_mapping.txt"
  
  if [[ -s "$BASE_DIR/tmp/puredns.snl" ]]; then
    # Filter for YOUR domain CNAMEs pointing to vulnerable services
    grep -Eai "\.${domain}\. CNAME.*(azurewebsites|cloudapp|azure-api|trafficmanager|blob\.core\.windows\.net|herokuapp|pantheonsite|ghost\.io|zendesk|github\.io|s3\.amazonaws|getbynder|bitly)" \
      "$BASE_DIR/tmp/puredns.snl" 2>/dev/null | \
      awk -v domain="$domain" '{
        # Only process if first column ends with our target domain
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

  # Combine YOUR subdomains only
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
fi

########################################
# HTTP DISCOVERY
########################################
if should_run http_discovery; then
  stage_header "6/8" "HTTP SERVICE DISCOVERY"

  HTTPX_JSON="$BASE_DIR/http_discovery/httpx_full.json"
  HTTPX_TXT="$BASE_DIR/http_discovery/httpx_full.txt"

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
    jq -r 'select(.status_code == 403) | .url' "$HTTPX_JSON" 2>/dev/null \
      > "$BASE_DIR/http_discovery/status_403.txt" || touch "$BASE_DIR/http_discovery/status_403.txt"
    jq -r 'select(.status_code == 404) | .url' "$HTTPX_JSON" 2>/dev/null \
      > "$BASE_DIR/http_discovery/status_404.txt" || touch "$BASE_DIR/http_discovery/status_404.txt"
    jq -r '.tech[]?' "$HTTPX_JSON" 2>/dev/null | sort -u \
      > "$BASE_DIR/http_discovery/technologies.txt" || touch "$BASE_DIR/http_discovery/technologies.txt"

    success "Live HTTP services: ${BOLD}${GREEN}$(wc -l < "$BASE_DIR/http_discovery/live_urls.txt" || echo 0)${RESET}"
    echo -e "    ${DIM}200 OK: ${GREEN}$(wc -l < "$BASE_DIR/http_discovery/status_200.txt" 2>/dev/null || echo 0)${RESET} ${DIM}| 403: ${YELLOW}$(wc -l < "$BASE_DIR/http_discovery/status_403.txt" 2>/dev/null || echo 0)${RESET}${RESET}"
  else
    warn "No httpx output generated"
    touch "$BASE_DIR/http_discovery/live_urls.txt"
  fi
fi

########################################
# HTTP EXPLOITATION
########################################
if should_run http_exploitation; then
  stage_header "7/8" "HIGH-VALUE TARGET IDENTIFICATION"

  progress "Identifying admin/api/auth endpoints..."
  grep -Eai '(admin|api|auth|login|dashboard|panel|console|staging|dev|test|internal)' \
    "$BASE_DIR/http_discovery/live_urls.txt" 2>/dev/null \
    | sort -u > "$BASE_DIR/http_exploitation/high_value_urls.txt" || touch "$BASE_DIR/http_exploitation/high_value_urls.txt"

  HV_COUNT=$(wc -l < "$BASE_DIR/http_exploitation/high_value_urls.txt" || echo 0)
  if [[ $HV_COUNT -gt 0 ]]; then
    success "High-value targets: ${BOLD}${YELLOW}$HV_COUNT${RESET}"
    [[ "$VERBOSE" == true ]] && head -10 "$BASE_DIR/http_exploitation/high_value_urls.txt" | sed 's/^/    /'
  else
    log "No high-value targets identified"
  fi
fi

########################################
# NUCLEI SCAN (ENHANCED)
########################################
if should_run nuclei; then
  stage_header "8/8" "VULNERABILITY SCANNING (NUCLEI)"

  run_nuclei_scan() {
    local target_file="$1"
    local templates="$2"
    local severity="$3"
    local output_file="$4"
    local description="$5"
    local exclude_tags="${6:-dos}"
    mkdir -p "$(dirname "$output_file")"

    if [[ ! -f "$target_file" ]] || [[ ! -s "$target_file" ]]; then
      log "Skip ${description}: No targets"
      return
    fi

    local count
    count=$(wc -l < "$target_file")
    progress "${CYAN}${description}${RESET} (${count} targets)"

    nuclei -l "$target_file" -t "$templates" -severity "$severity" -et "$exclude_tags" \
      -o "$output_file" -json-export "${output_file}.json" -silent \
      -timeout 10 -retries 1 -rate-limit 100 -bulk-size 25 -concurrency 15 \
      -max-host-error 10 -follow-host-redirects \
      -disable-update-check 2>"${output_file}_error.log" || true

    local results
    results=$(wc -l < "$output_file" 2>/dev/null || echo 0)
    if [[ $results -gt 0 ]]; then
      success "${description}: ${GREEN}${results}${RESET} findings"
    else
      log "${description}: No findings"
    fi
  }

  # Optimize targets
  if [[ -f "$BASE_DIR/http_discovery/live_urls.txt" ]] && [[ -s "$BASE_DIR/http_discovery/live_urls.txt" ]]; then
    progress "Optimizing target URLs..."
    {
      cat "$BASE_DIR/http_discovery/live_urls.txt"
      while IFS= read -r url; do
        base=$(echo "$url" | sed 's/\/$//')
        for path in /admin /login /api /v1 /graphql /console /.env /config.json /swagger.json; do
          echo "$base$path"
        done
      done < "$BASE_DIR/http_discovery/live_urls.txt"
    } | sort -u > "$BASE_DIR/nuclei/optimized_targets.txt"
    success "Optimized: $(wc -l < "$BASE_DIR/nuclei/optimized_targets.txt") URLs"
  else
    touch "$BASE_DIR/nuclei/optimized_targets.txt"
    warn "No live URLs found, skipping nuclei scan"
    exit 0
  fi

  # Phase 1: Quick Wins
  progress "Phase 1: Quick Win Detection"
  run_nuclei_scan "$BASE_DIR/nuclei/optimized_targets.txt" \
    "$NUCLEI_TEMPLATES/http/exposures/,$NUCLEI_TEMPLATES/file/" \
    "info,low,medium,high,critical" "$BASE_DIR/nuclei/raw/exposed_files.txt" "Exposed Files"

  run_nuclei_scan "$BASE_DIR/nuclei/optimized_targets.txt" \
    "$NUCLEI_TEMPLATES/http/default-logins/" \
    "medium,high,critical" "$BASE_DIR/nuclei/raw/default_creds.txt" "Default Credentials"

  run_nuclei_scan "$BASE_DIR/nuclei/optimized_targets.txt" \
    "$NUCLEI_TEMPLATES/http/exposed-panels/" \
    "info,low,medium,high,critical" "$BASE_DIR/nuclei/raw/admin_panels.txt" "Admin Panels"

  if [[ -f "$BASE_DIR/recon_intel/takeover_candidates.txt" ]] && [[ -s "$BASE_DIR/recon_intel/takeover_candidates.txt" ]]; then
    run_nuclei_scan "$BASE_DIR/recon_intel/takeover_candidates.txt" \
      "$NUCLEI_TEMPLATES/http/takeovers/,$NUCLEI_TEMPLATES/dns/" \
      "info,low,medium,high,critical" "$BASE_DIR/nuclei/raw/subdomain_takeover.txt" "Subdomain Takeover"
  fi

  # Phase 2: Technology Detection
  progress "Phase 2: Technology Fingerprinting"
  run_nuclei_scan "$BASE_DIR/nuclei/optimized_targets.txt" \
    "$NUCLEI_TEMPLATES/http/technologies/" \
    "info" "$BASE_DIR/nuclei/raw/tech_detection.txt" \
    "Technology Detection" "dos,fuzz,intrusive"

  # Tech-specific scans
  if [[ -f "$BASE_DIR/nuclei/raw/tech_detection.txt" ]] && [[ -s "$BASE_DIR/nuclei/raw/tech_detection.txt" ]]; then
    if grep -qi "wordpress" "$BASE_DIR/nuclei/raw/tech_detection.txt" 2>/dev/null; then
      run_nuclei_scan "$BASE_DIR/nuclei/optimized_targets.txt" \
        "$NUCLEI_TEMPLATES/http/misconfiguration/wordpress/,$NUCLEI_TEMPLATES/http/vulnerabilities/wordpress/" \
        "medium,high,critical" "$BASE_DIR/nuclei/raw/wordpress.txt" "WordPress"
    fi

    if grep -qi "jenkins" "$BASE_DIR/nuclei/raw/tech_detection.txt" 2>/dev/null; then
      run_nuclei_scan "$BASE_DIR/nuclei/optimized_targets.txt" \
        "$NUCLEI_TEMPLATES/http/misconfiguration/jenkins/,$NUCLEI_TEMPLATES/http/vulnerabilities/jenkins/" \
        "medium,high,critical" "$BASE_DIR/nuclei/raw/jenkins.txt" "Jenkins"
    fi

    if grep -qi "jira" "$BASE_DIR/nuclei/raw/tech_detection.txt" 2>/dev/null; then
      run_nuclei_scan "$BASE_DIR/nuclei/optimized_targets.txt" \
        "$NUCLEI_TEMPLATES/http/vulnerabilities/atlassian/" \
        "medium,high,critical" "$BASE_DIR/nuclei/raw/jira.txt" "Jira/Atlassian"
    fi
  fi

  # Phase 3: Critical CVEs
  progress "Phase 3: Critical Vulnerabilities"
  run_nuclei_scan "$BASE_DIR/nuclei/optimized_targets.txt" \
    "$NUCLEI_TEMPLATES/http/cves/2024/,$NUCLEI_TEMPLATES/http/cves/2023/" \
    "high,critical" "$BASE_DIR/nuclei/raw/recent_cves.txt" "Recent CVEs (2023-2024)"

  run_nuclei_scan "$BASE_DIR/nuclei/optimized_targets.txt" \
    "$NUCLEI_TEMPLATES/http/cves/" \
    "critical" "$BASE_DIR/nuclei/raw/critical_cves.txt" "All Critical CVEs"

  run_nuclei_scan "$BASE_DIR/nuclei/optimized_targets.txt" \
    "$NUCLEI_TEMPLATES/http/vulnerabilities/" \
    "high,critical" "$BASE_DIR/nuclei/raw/common_vulns.txt" "Common Vulnerabilities"

  # Phase 4: Misconfigurations
  progress "Phase 4: Misconfigurations & Secrets"
  run_nuclei_scan "$BASE_DIR/nuclei/optimized_targets.txt" \
    "$NUCLEI_TEMPLATES/http/misconfiguration/" \
    "low,medium,high,critical" "$BASE_DIR/nuclei/raw/misconfigs.txt" "Misconfigurations" "dos,fuzz,intrusive"

  run_nuclei_scan "$BASE_DIR/nuclei/optimized_targets.txt" \
    "$NUCLEI_TEMPLATES/http/token-spray/,$NUCLEI_TEMPLATES/http/exposures/tokens/" \
    "medium,high,critical" "$BASE_DIR/nuclei/raw/tokens.txt" "API Keys & Tokens"

  # Phase 5: Custom templates (if exist)
  if [[ -d "$CUSTOM_NUCLEI_TEMPLATES/secrets" ]]; then
    run_nuclei_scan "$BASE_DIR/nuclei/optimized_targets.txt" \
      "$CUSTOM_NUCLEI_TEMPLATES/secrets/" \
      "medium,high,critical" "$BASE_DIR/nuclei/raw/custom_secrets.txt" "Custom Secret Detection"
  fi

  # Phase 6: Conditional comprehensive scan
  progress "Phase 6: Adaptive Scanning Strategy"
  TARGET_COUNT=$(wc -l < "$BASE_DIR/nuclei/optimized_targets.txt" 2>/dev/null || echo 0)
  echo -e "    ${DIM}Target count: ${YELLOW}$TARGET_COUNT${RESET}"
  
  if [[ $TARGET_COUNT -le 50 ]]; then
    progress "Small target set ($TARGET_COUNT) - launching deep comprehensive scan"
    run_nuclei_scan "$BASE_DIR/nuclei/optimized_targets.txt" "$NUCLEI_TEMPLATES/" \
      "info,low,medium,high,critical" "$BASE_DIR/nuclei/raw/comprehensive.txt" \
      "Comprehensive Deep Scan" "dos,fuzz,intrusive,headless"
  elif [[ $TARGET_COUNT -le 200 ]]; then
    progress "Medium target set ($TARGET_COUNT) - launching focused scan"
    run_nuclei_scan "$BASE_DIR/nuclei/optimized_targets.txt" "$NUCLEI_TEMPLATES/http/" \
      "low,medium,high,critical" "$BASE_DIR/nuclei/raw/focused.txt" \
      "Focused HTTP Scan" "dos,fuzz,intrusive"
  else
    progress "Large target set ($TARGET_COUNT) - quick critical-only scan"
    run_nuclei_scan "$BASE_DIR/nuclei/optimized_targets.txt" "$NUCLEI_TEMPLATES/http/" \
      "high,critical" "$BASE_DIR/nuclei/raw/quick_critical.txt" \
      "Quick Critical Scan" "dos,fuzz,intrusive,headless"
  fi

  # Aggregate results
  progress "Aggregating results..."
  cat "$BASE_DIR/nuclei/raw/"*.txt 2>/dev/null | sort -u > "$BASE_DIR/nuclei/processed/all_findings.txt" || touch "$BASE_DIR/nuclei/processed/all_findings.txt"
  grep -Ei '\[critical\]' "$BASE_DIR/nuclei/raw/"*.txt 2>/dev/null | sort -u > "$BASE_DIR/nuclei/processed/CRITICAL.txt" || touch "$BASE_DIR/nuclei/processed/CRITICAL.txt"
  grep -Ei '\[high\]' "$BASE_DIR/nuclei/raw/"*.txt 2>/dev/null | sort -u > "$BASE_DIR/nuclei/processed/HIGH.txt" || touch "$BASE_DIR/nuclei/processed/HIGH.txt"
  grep -Ei '\[medium\]' "$BASE_DIR/nuclei/raw/"*.txt 2>/dev/null | sort -u > "$BASE_DIR/nuclei/processed/MEDIUM.txt" || touch "$BASE_DIR/nuclei/processed/MEDIUM.txt"

  jq -s 'add' "$BASE_DIR/nuclei/json/"*.json 2>/dev/null > "$BASE_DIR/nuclei/processed/all_findings.json" || echo "[]" > "$BASE_DIR/nuclei/processed/all_findings.json"

  # Generate summary
  CRIT=$(wc -l < "$BASE_DIR/nuclei/processed/CRITICAL.txt" 2>/dev/null || echo 0)
  HIGH=$(wc -l < "$BASE_DIR/nuclei/processed/HIGH.txt" 2>/dev/null || echo 0)
  MED=$(wc -l < "$BASE_DIR/nuclei/processed/MEDIUM.txt" 2>/dev/null || echo 0)
  ALL=$(wc -l < "$BASE_DIR/nuclei/processed/all_findings.txt" 2>/dev/null || echo 0)

  {
    echo "================================================================="
    echo "NUCLEI SCAN SUMMARY - $(date)"
    echo "================================================================="
    echo "Critical: $CRIT | High: $HIGH | Medium: $MED | Total: $ALL"
    echo ""
    if [[ $CRIT -gt 0 ]]; then
      echo "CRITICAL FINDINGS:"
      head -30 "$BASE_DIR/nuclei/processed/CRITICAL.txt"
    fi
    if [[ $HIGH -gt 0 ]]; then
      echo ""
      echo "HIGH FINDINGS:"
      head -20 "$BASE_DIR/nuclei/processed/HIGH.txt"
    fi
  } > "$BASE_DIR/nuclei/SCAN_SUMMARY.txt"

  if [[ $CRIT -gt 0 ]]; then
    warn "⚠️  Critical: ${RED}$CRIT${RESET}"
  fi
  if [[ $HIGH -gt 0 ]]; then
    warn "⚠️  High: ${YELLOW}$HIGH${RESET}"
  fi
  if [[ $ALL -gt 0 ]]; then
    success "✓ Total findings: ${GREEN}$ALL${RESET}"
  else
    log "No vulnerabilities detected"
  fi

  cp "$BASE_DIR/nuclei/processed/CRITICAL.txt" "$BASE_DIR/nuclei/CRITICAL_FINDINGS.txt" 2>/dev/null || true
fi

########################################
# FINAL SUMMARY
########################################
echo ""
echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║${RESET}               ${BOLD}${GREEN}RECONNAISSANCE COMPLETE${RESET}                      ${CYAN}║${RESET}"
echo -e "${CYAN}╠════════════════════════════════════════════════════════════════╣${RESET}"
echo -e "${CYAN}║${RESET}  Target: ${YELLOW}${BOLD}$(printf '%-50s' "$domain")${RESET} ${CYAN}║${RESET}"
echo -e "${CYAN}╠════════════════════════════════════════════════════════════════╣${RESET}"
echo -e "${CYAN}║${RESET}  ${BOLD}Discovery Statistics${RESET}                                    ${CYAN}║${RESET}"
echo -e "${CYAN}║${RESET}  ├─ Domains Found:      ${GREEN}$(printf '%6s' "$(wc -l < "$BASE_DIR/dns/resolved_domains.txt" 2>/dev/null || echo 0)")${RESET}                         ${CYAN}║${RESET}"
echo -e "${CYAN}║${RESET}  ├─ Live HTTP:          ${GREEN}$(printf '%6s' "$(wc -l < "$BASE_DIR/http_discovery/live_urls.txt" 2>/dev/null || echo 0)")${RESET}                         ${CYAN}║${RESET}"
echo -e "${CYAN}║${RESET}  ├─ Status 200:         ${GREEN}$(printf '%6s' "$(wc -l < "$BASE_DIR/http_discovery/status_200.txt" 2>/dev/null || echo 0)")${RESET}                         ${CYAN}║${RESET}"
echo -e "${CYAN}║${RESET}  ├─ Status 403:         ${YELLOW}$(printf '%6s' "$(wc -l < "$BASE_DIR/http_discovery/status_403.txt" 2>/dev/null || echo 0)")${RESET}                         ${CYAN}║${RESET}"
echo -e "${CYAN}║${RESET}  └─ High-Value Targets: ${YELLOW}$(printf '%6s' "$(wc -l < "$BASE_DIR/http_exploitation/high_value_urls.txt" 2>/dev/null || echo 0)")${RESET}                         ${CYAN}║${RESET}"
echo -e "${CYAN}║${RESET}                                                                ${CYAN}║${RESET}"
echo -e "${CYAN}║${RESET}  ${BOLD}Security Intelligence${RESET}                                   ${CYAN}║${RESET}"
echo -e "${CYAN}║${RESET}  ├─ Cloud Assets:       ${CYAN}$(printf '%6s' "$(wc -l < "$BASE_DIR/recon_intel/cloud_assets.txt" 2>/dev/null || echo 0)")${RESET}                         ${CYAN}║${RESET}"
echo -e "${CYAN}║${RESET}  ├─ Takeover Risks:     ${YELLOW}$(printf '%6s' "$(wc -l < "$BASE_DIR/recon_intel/takeover_candidates.txt" 2>/dev/null || echo 0)")${RESET}                         ${CYAN}║${RESET}"
echo -e "${CYAN}║${RESET}  └─ Critical Findings:  ${RED}$(printf '%6s' "$(wc -l < "$BASE_DIR/nuclei/CRITICAL_FINDINGS.txt" 2>/dev/null || echo 0)")${RESET}                         ${CYAN}║${RESET}"
echo -e "${CYAN}╠════════════════════════════════════════════════════════════════╣${RESET}"
echo -e "${CYAN}║${RESET}  ${BOLD}Output Location${RESET}                                         ${CYAN}║${RESET}"
echo -e "${CYAN}║${RESET}  ${DIM}$(printf '%-60s' "$BASE_DIR")${RESET}  ${CYAN}║${RESET}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${RESET}"

# Generate detailed report
{
  echo "╔════════════════════════════════════════════════════════════════╗"
  echo "║          RECONNAISSANCE REPORT - $domain"
  echo "║          Generated: $(date '+%F %T')"
  echo "╚════════════════════════════════════════════════════════════════╝"
  echo ""
  echo "═══ DISCOVERY STATISTICS ═══"
  echo ""
  echo "Enumeration Results:"
  echo "  • Total Domains Discovered:    $(wc -l < "$BASE_DIR/dns/resolved_domains.txt" 2>/dev/null || echo 0)"
  echo "  • Live HTTP Services:          $(wc -l < "$BASE_DIR/http_discovery/live_urls.txt" 2>/dev/null || echo 0)"
  echo "  • Unique Technologies:         $(wc -l < "$BASE_DIR/http_discovery/technologies.txt" 2>/dev/null || echo 0)"
  echo ""
  echo "HTTP Status Breakdown:"
  echo "  • 200 OK:                      $(wc -l < "$BASE_DIR/http_discovery/status_200.txt" 2>/dev/null || echo 0)"
  echo "  • 401 Unauthorized:            $(wc -l < "$BASE_DIR/http_discovery/status_401.txt" 2>/dev/null || echo 0)"
  echo "  • 403 Forbidden:               $(wc -l < "$BASE_DIR/http_discovery/status_403.txt" 2>/dev/null || echo 0)"
  echo "  • 404 Not Found:               $(wc -l < "$BASE_DIR/http_discovery/status_404.txt" 2>/dev/null || echo 0)"
  echo "  • 5xx Server Errors:           $(wc -l < "$BASE_DIR/http_discovery/status_5xx.txt" 2>/dev/null || echo 0)"
  echo ""
  echo "═══ HIGH-VALUE TARGETS ═══"
  echo ""
  HV_COUNT=$(wc -l < "$BASE_DIR/http_exploitation/high_value_urls.txt" 2>/dev/null || echo 0)
  if [[ $HV_COUNT -gt 0 ]]; then
    echo "Admin/API/Auth Endpoints ($HV_COUNT total):"
    head -15 "$BASE_DIR/http_exploitation/high_value_urls.txt" 2>/dev/null | sed 's/^/  • /' || echo "  None"
    [[ $HV_COUNT -gt 15 ]] && echo "  ... and $((HV_COUNT - 15)) more"
  else
    echo "No high-value targets identified"
  fi
  echo ""
  echo "═══ SECURITY FINDINGS ═══"
  echo ""
  CRIT_COUNT=$(wc -l < "$BASE_DIR/nuclei/CRITICAL_FINDINGS.txt" 2>/dev/null || echo 0)
  echo "Critical/High Severity Issues: $CRIT_COUNT"
  echo ""
  if [[ $CRIT_COUNT -gt 0 ]]; then
    echo "Top Findings:"
    head -25 "$BASE_DIR/nuclei/CRITICAL_FINDINGS.txt" 2>/dev/null | sed 's/^/  • /' || echo "  None"
    [[ $CRIT_COUNT -gt 25 ]] && echo "  ... and $((CRIT_COUNT - 25)) more (see nuclei/CRITICAL_FINDINGS.txt)"
  fi
  echo ""
  echo "═══ CLOUD INFRASTRUCTURE ═══"
  echo ""
  CLOUD_COUNT=$(wc -l < "$BASE_DIR/recon_intel/cloud_assets.txt" 2>/dev/null || echo 0)
  echo "Cloud-Hosted Assets: $CLOUD_COUNT"
  if [[ $CLOUD_COUNT -gt 0 ]]; then
    echo ""
    head -10 "$BASE_DIR/recon_intel/cloud_assets.txt" 2>/dev/null | sed 's/^/  • /' || echo "  None"
    [[ $CLOUD_COUNT -gt 10 ]] && echo "  ... and $((CLOUD_COUNT - 10)) more"
  fi
  echo ""
  TAKEOVER_COUNT=$(wc -l < "$BASE_DIR/recon_intel/takeover_candidates.txt" 2>/dev/null || echo 0)
  echo "Potential Subdomain Takeover Candidates: $TAKEOVER_COUNT"
  if [[ $TAKEOVER_COUNT -gt 0 ]]; then
    echo ""
    echo "⚠️  PRIORITY: Review these for subdomain takeover vulnerabilities"
    head -15 "$BASE_DIR/recon_intel/takeover_candidates.txt" 2>/dev/null | sed 's/^/  • /' || echo "  None"
    [[ $TAKEOVER_COUNT -gt 15 ]] && echo "  ... and $((TAKEOVER_COUNT - 15)) more"
  fi
  echo ""
  echo "═══ DETECTED TECHNOLOGIES ═══"
  echo ""
  TECH_COUNT=$(wc -l < "$BASE_DIR/http_discovery/technologies.txt" 2>/dev/null || echo 0)
  if [[ $TECH_COUNT -gt 0 ]]; then
    head -25 "$BASE_DIR/http_discovery/technologies.txt" 2>/dev/null | sed 's/^/  • /' || echo "  None"
    [[ $TECH_COUNT -gt 25 ]] && echo "  ... and $((TECH_COUNT - 25)) more"
  else
    echo "No technologies detected"
  fi
  echo ""
  echo "═══ FILE LOCATIONS ═══"
  echo ""
  echo "Results Directory:     $BASE_DIR"
  echo "Logs:                  $BASE_DIR/logs/recon.log"
  echo "Live URLs:             $BASE_DIR/http_discovery/live_urls.txt"
  echo "Critical Findings:     $BASE_DIR/nuclei/CRITICAL_FINDINGS.txt"
  echo "Takeover Candidates:   $BASE_DIR/recon_intel/takeover_candidates.txt"
  echo ""
  echo "╔════════════════════════════════════════════════════════════════╗"
  echo "║  End of Report - $(date '+%F %T')"
  echo "╚════════════════════════════════════════════════════════════════╝"
} > "$BASE_DIR/FINAL_REPORT.txt"

echo ""
success "Final report saved: ${CYAN}$BASE_DIR/FINAL_REPORT.txt${RESET}"
echo ""

if [[ "$VERBOSE" == true ]]; then
  cat "$BASE_DIR/FINAL_REPORT.txt"
fi
