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

Example:
  ./recon.sh example.com
  ./recon.sh example.com --from passive
  ./recon.sh example.com --base-dir output
EOF
}

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
    *)
      domain="$1"; shift ;;
  esac
done

[[ -z "$domain" ]] && { show_help; exit 1; }

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
NUCLEI_CONCURRENCY=30  # Nuclei parallel scans
NUCLEI_RATE=200        # Nuclei requests per second
NUCLEI_TIMEOUT=10      # Timeout for each template in seconds

RESOLVERS="$HOME/resolvers.txt"
WORDLIST="$HOME/wordlists/dns.txt"
ALTDNS_WORDLIST="$HOME/wordlists/altdns_words.txt"
NUCLEI_TEMPLATES="$HOME/nuclei-templates"
AMASS_CONFIG="$HOME/.config/amass/config.yaml"

OUTPUT_ROOT="${OUTPUT_ROOT:-$PROJECT_ROOT/output}"
BASE_DIR="$OUTPUT_ROOT/$domain"

mkdir -p "$BASE_DIR"/{passive,bruteforce,permutations,dns,final,tmp,logs,recon_intel,http_discovery,http_exploitation,nuclei}

LOG_FILE="$BASE_DIR/logs/recon.log"
mkdir -p "$(dirname "$LOG_FILE")"
exec >>"$LOG_FILE" 2>&1

log(){ echo "[*] $(date '+%F %T') :: $*"; }
warn(){ echo "[!] $(date '+%F %T') :: $*"; }

safe_cat(){ for f in "$@"; do [[ -s "$f" ]] && cat "$f"; done; }

need(){
  [[ -s "$1" ]] || { warn "Missing dependency: $1 (run $2)"; exit 1; }
}

# Clean up empty files at the end
cleanup_empty_files() {
  local dir="$1"
  log "Cleaning up empty files in $dir..."
  find "$dir" -type f -empty -delete 2>/dev/null || true
}

########################################
# TOOL CHECKS
########################################
log "Checking required tools..."
MISSING_TOOLS=()

for t in subfinder assetfinder amass puredns dnsgen altdns httpx nuclei awk sed grep sort cut; do
  if ! command -v "$t" >/dev/null 2>&1; then
    MISSING_TOOLS+=("$t")
  fi
done

if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
  echo ""
  echo "[!] Missing required tools: ${MISSING_TOOLS[*]}"
  echo ""
  echo "Run './install.sh' to install missing tools, or install them manually:"
  echo ""
  echo "  subfinder:    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  echo "  assetfinder:  go install -v github.com/tomnomnom/assetfinder@latest"
  echo "  amass:        apt-get install amass  OR  go install -v github.com/owasp-amass/amass/v4/...@master"
  echo "  puredns:      go install github.com/d3mondev/puredns/v2@latest"
  echo "  dnsgen:       python3 -m pip install dnsgen"
  echo "  altdns:       pip3 install py-altdns==1.0.2"
  echo "  httpx:        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
  echo "  nuclei:       go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  echo ""
  exit 1
fi

log "All tools found ✓"

########################################
# PASSIVE
########################################
if should_run passive; then
  log "STAGE: passive"

  # Subfinder with all sources
  log "Running subfinder..."
  subfinder -d "$domain" -silent -all > "$BASE_DIR/passive/subfinder.txt" || true
  log "Subfinder found: $(wc -l < "$BASE_DIR/passive/subfinder.txt" 2>/dev/null || echo 0) domains"
  
  # Assetfinder
  log "Running assetfinder..."
  assetfinder --subs-only "$domain" > "$BASE_DIR/passive/assetfinder.txt" || true
  log "Assetfinder found: $(wc -l < "$BASE_DIR/passive/assetfinder.txt" 2>/dev/null || echo 0) domains"
  
  # Amass passive enumeration with proper configuration for v4
  log "Running amass passive enumeration (may take 3-10 minutes)..."
  
  if [[ -s "$AMASS_CONFIG" ]]; then
    # Create temporary config with domain in scope
    TEMP_AMASS_CONFIG="$BASE_DIR/tmp/amass_config_temp.yaml"
    cp "$AMASS_CONFIG" "$TEMP_AMASS_CONFIG"
    
    # Add domain to scope in temp config
    sed -i "/^scope:/a\\  domains:\\n    - $domain" "$TEMP_AMASS_CONFIG"
    
    # Run amass with timeout and verbose logging
    timeout 600 amass enum \
      -config "$TEMP_AMASS_CONFIG" \
      -passive \
      -timeout 10 \
      -v \
      -o "$BASE_DIR/passive/amass.txt" \
      2>"$BASE_DIR/logs/amass_verbose.log" || {
        EXIT_CODE=$?
        if [ $EXIT_CODE -eq 124 ]; then
          warn "Amass reached 10 minute timeout (normal for passive mode)"
        else
          warn "Amass exited with code $EXIT_CODE (check $BASE_DIR/logs/amass_verbose.log)"
        fi
      }
    
    # Clean up temp config
    rm -f "$TEMP_AMASS_CONFIG"
  else
    warn "Amass config not found: $AMASS_CONFIG"
    warn "Running amass without config (limited data sources)"
    
    timeout 600 amass enum \
      -d "$domain" \
      -passive \
      -timeout 10 \
      -v \
      -o "$BASE_DIR/passive/amass.txt" \
      2>"$BASE_DIR/logs/amass_verbose.log" || {
        warn "Amass failed or timed out"
      }
  fi
  
  log "Amass found: $(wc -l < "$BASE_DIR/passive/amass.txt" 2>/dev/null || echo 0) domains"
  
  # Show what amass is doing (last 5 lines of log)
  if [[ -s "$BASE_DIR/logs/amass_verbose.log" ]]; then
    log "Amass activity (last 5 lines):"
    tail -5 "$BASE_DIR/logs/amass_verbose.log" | while read line; do
      log "  $line"
    done
  fi

  # Combine and deduplicate
  safe_cat "$BASE_DIR/passive/"*.txt | sort -u \
    > "$BASE_DIR/passive/passive_seeds.txt"

  log "Total passive seeds: $(wc -l < "$BASE_DIR/passive/passive_seeds.txt" 2>/dev/null || echo 0)"
fi

########################################
# BRUTEFORCE
########################################
if should_run bruteforce; then
  log "STAGE: bruteforce"

  [[ -s "$WORDLIST" ]] || { warn "WORDLIST missing: $WORDLIST"; exit 1; }
  [[ -s "$RESOLVERS" ]] || { warn "RESOLVERS missing: $RESOLVERS"; exit 1; }

  # Bruteforce DNS names
  puredns bruteforce "$WORDLIST" "$domain" \
    -r "$RESOLVERS" \
    --rate-limit-trusted 400 \
    -w "$BASE_DIR/bruteforce/raw.txt"

  # Resolve and filter wildcards
  puredns resolve "$BASE_DIR/bruteforce/raw.txt" \
    -r "$RESOLVERS" \
    --wildcard-tests 3 \
    -w "$BASE_DIR/bruteforce/resolved.txt" || true

  # Combine with passive seeds
  safe_cat "$BASE_DIR/passive/passive_seeds.txt" \
           "$BASE_DIR/bruteforce/resolved.txt" \
    | sort -u > "$BASE_DIR/final/resolved_fqdns.txt"
  
  log "Bruteforce + Passive count: $(wc -l < "$BASE_DIR/final/resolved_fqdns.txt" 2>/dev/null || echo 0)"
fi

########################################
# PERMUTATIONS
########################################
if should_run permutations; then
  log "STAGE: permutations"
  need "$BASE_DIR/final/resolved_fqdns.txt" "bruteforce"

  # Generate permutations with dnsgen
  log "Running dnsgen..."
  dnsgen "$BASE_DIR/final/resolved_fqdns.txt" \
    > "$BASE_DIR/permutations/dnsgen_raw.txt" || true

  # Filter out invalid dnsgen results (ASN announcements, malformed domains)
  log "Filtering dnsgen output..."
  grep -E "^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.$domain$" \
    "$BASE_DIR/permutations/dnsgen_raw.txt" 2>/dev/null \
    | grep -v -E "(asn|announces|cname_record|--|\.\.|^\.|^>)" \
    | sort -u > "$BASE_DIR/permutations/dnsgen_filtered.txt" || true

  log "Dnsgen valid: $(wc -l < "$BASE_DIR/permutations/dnsgen_filtered.txt" 2>/dev/null || echo 0) (filtered from $(wc -l < "$BASE_DIR/permutations/dnsgen_raw.txt" 2>/dev/null || echo 0))"

  # Extract subdomain labels for altdns
  sed "s/\\.$domain\$//" "$BASE_DIR/final/resolved_fqdns.txt" \
    | cut -d'.' -f1 | sort -u \
    > "$BASE_DIR/permutations/base_labels.txt"

  # Generate altdns permutations
  if [[ -s "$ALTDNS_WORDLIST" ]] && [[ -s "$BASE_DIR/permutations/base_labels.txt" ]]; then
    log "Running altdns..."
    altdns -i "$BASE_DIR/permutations/base_labels.txt" \
           -w "$ALTDNS_WORDLIST" \
           -o "$BASE_DIR/permutations/altdns_raw.txt" \
           -t 50 || true
    
    # Add domain suffix to altdns output
    sed "s/$/.$domain/" "$BASE_DIR/permutations/altdns_raw.txt" \
      > "$BASE_DIR/permutations/altdns_fqdns.txt"
    
    log "Altdns generated: $(wc -l < "$BASE_DIR/permutations/altdns_fqdns.txt" 2>/dev/null || echo 0)"
  else
    warn "Skipping altdns (missing wordlist or labels)"
    : > "$BASE_DIR/permutations/altdns_fqdns.txt"
  fi

  # Combine all permutations and filter valid patterns
  {
    [[ -s "$BASE_DIR/permutations/dnsgen_filtered.txt" ]] && cat "$BASE_DIR/permutations/dnsgen_filtered.txt"
    [[ -s "$BASE_DIR/permutations/altdns_fqdns.txt" ]] && cat "$BASE_DIR/permutations/altdns_fqdns.txt"
  } | grep -E "\.$domain$" \
    | sort -u > "$BASE_DIR/permutations/all_permutations.txt"

  log "Total permutations: $(wc -l < "$BASE_DIR/permutations/all_permutations.txt" 2>/dev/null || echo 0)"
fi

########################################
# DNS
########################################
if should_run dns; then
  log "STAGE: dns"

  # Combine all FQDNs
  safe_cat "$BASE_DIR/final/resolved_fqdns.txt" \
           "$BASE_DIR/permutations/all_permutations.txt" \
    | sort -u > "$BASE_DIR/dns/all_candidates.txt"

  log "Total DNS candidates: $(wc -l < "$BASE_DIR/dns/all_candidates.txt" 2>/dev/null || echo 0)"

  # Resolve all candidates with wildcard filtering
  puredns resolve "$BASE_DIR/dns/all_candidates.txt" \
    -r "$RESOLVERS" \
    --wildcard-tests 5 \
    --write-massdns "$BASE_DIR/tmp/puredns.snl" || true

  # Extract resolved FQDNs only (remove IPs)
  awk '{print $1}' "$BASE_DIR/tmp/puredns.snl" 2>/dev/null \
    | sed 's/\.$//' | sort -u \
    > "$BASE_DIR/dns/resolved_domains.txt"

  # Create DNS to IP mapping
  awk '{print $1, $3}' "$BASE_DIR/tmp/puredns.snl" 2>/dev/null \
    | sed 's/\.$//' | sort -u \
    > "$BASE_DIR/dns/dns_to_ip_map.txt"

  # Extract only IPs
  awk '{print $3}' "$BASE_DIR/tmp/puredns.snl" 2>/dev/null \
    | grep -Eo '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' \
    | sort -u > "$BASE_DIR/dns/resolved_ips.txt"

  log "Resolved domains: $(wc -l < "$BASE_DIR/dns/resolved_domains.txt" 2>/dev/null || echo 0)"
  log "Unique IPs: $(wc -l < "$BASE_DIR/dns/resolved_ips.txt" 2>/dev/null || echo 0)"
fi

########################################
# RECON INTEL
########################################
if should_run recon_intel; then
  log "STAGE: recon_intel"

  # Cloud assets detection
  grep -Eai 'amazonaws|azure|cloudfront|googleusercontent|cloudflare|fastly|akamai' \
    "$BASE_DIR/dns/dns_to_ip_map.txt" \
    > "$BASE_DIR/recon_intel/cloud_assets.txt" 2>/dev/null || true

  # Subdomain takeover candidates - improved patterns
  grep -Eo '^[^ ]+' "$BASE_DIR/dns/dns_to_ip_map.txt" 2>/dev/null | grep -Eai \
    'herokuapp\.com|github\.io|s3\.amazonaws\.com|s3-website|' \
'elasticbeanstalk\.com|azurewebsites\.net|cloudapp\.azure\.com|' \
'trafficmanager\.net|blob\.core\.windows\.net|cloudapp\.net|' \
'azureedge\.net|fastly\.net|netlify\.app|vercel\.app|' \
'zendesk\.com|bitbucket\.io|ghost\.io|readme\.io|' \
'pantheonsite\.io|surge\.sh|shopify\.com|desk\.com' \
    | sort -u > "$BASE_DIR/recon_intel/takeover_candidates.txt" 2>/dev/null || true

  # Extract third-party services
  grep -Eo '^[^ ]+' "$BASE_DIR/dns/dns_to_ip_map.txt" 2>/dev/null | grep -Eai \
    'zendesk|atlassian|salesforce|shopify|wordpress|wix' \
    | sort -u > "$BASE_DIR/recon_intel/third_party_services.txt" 2>/dev/null || true

  # Identify wildcards (multiple subdomains pointing to same IP)
  awk '{print $2}' "$BASE_DIR/dns/dns_to_ip_map.txt" 2>/dev/null | sort | uniq -c | sort -rn \
    | awk '$1 > 5 {print $2}' \
    > "$BASE_DIR/recon_intel/potential_wildcards.txt" 2>/dev/null || true

  log "Cloud assets: $(wc -l < "$BASE_DIR/recon_intel/cloud_assets.txt" 2>/dev/null || echo 0)"
  log "Takeover candidates: $(wc -l < "$BASE_DIR/recon_intel/takeover_candidates.txt" 2>/dev/null || echo 0)"
  log "Third-party services: $(wc -l < "$BASE_DIR/recon_intel/third_party_services.txt" 2>/dev/null || echo 0)"
fi

########################################
# HTTP DISCOVERY
########################################
if should_run http_discovery; then
  log "STAGE: http_discovery"

  # Only scan domain names, NOT IP addresses
  httpx -l "$BASE_DIR/dns/resolved_domains.txt" \
    -threads "$HTTP_THREADS" \
    -rate-limit "$HTTP_RATE" \
    -status-code -title -tech-detect -silent \
    -follow-redirects \
    -o "$BASE_DIR/http_discovery/httpx_full.txt" || true

  # Extract live URLs
  awk '{print $1}' "$BASE_DIR/http_discovery/httpx_full.txt" \
    | sort -u > "$BASE_DIR/http_discovery/live_urls.txt"

  # Extract by status code
  grep '\[200\]' "$BASE_DIR/http_discovery/httpx_full.txt" 2>/dev/null | awk '{print $1}' \
    > "$BASE_DIR/http_discovery/status_200.txt" || true
  
  grep '
