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
NUCLEI_CONCURRENCY=25  # Nuclei parallel scans
NUCLEI_RATE=150  # Nuclei requests per second

RESOLVERS="$HOME/resolvers.txt"
WORDLIST="$HOME/wordlists/dns.txt"
ALTDNS_WORDLIST="$HOME/wordlists/altdns_words.txt"
NUCLEI_TEMPLATES="$HOME/nuclei-templates"
AMASS_CONFIG="/home/ubuntu/.config/amass/config.yaml"
AMASS_DATASOURCES="/home/ubuntu/.config/amass/datasources.yaml"

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

########################################
# TOOL CHECKS
########################################
for t in subfinder assetfinder amass puredns dnsgen altdns httpx nuclei awk sed grep sort cut; do
  command -v "$t" >/dev/null || { echo "[!] Missing tool: $t"; exit 1; }
done

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
  dnsgen "$BASE_DIR/final/resolved_fqdns.txt" \
    > "$BASE_DIR/permutations/dnsgen_raw.txt" || true

  # Extract subdomain labels for altdns
  sed "s/\\.$domain\$//" "$BASE_DIR/final/resolved_fqdns.txt" \
    | cut -d'.' -f1 | sort -u \
    > "$BASE_DIR/permutations/base_labels.txt"

  # Generate altdns permutations
  if [[ -s "$ALTDNS_WORDLIST" ]] && [[ -s "$BASE_DIR/permutations/base_labels.txt" ]]; then
    altdns -i "$BASE_DIR/permutations/base_labels.txt" \
           -w "$ALTDNS_WORDLIST" \
           -o "$BASE_DIR/permutations/altdns_raw.txt" \
           -t 50 || true
    
    # Add domain suffix to altdns output
    sed "s/$/.$domain/" "$BASE_DIR/permutations/altdns_raw.txt" \
      > "$BASE_DIR/permutations/altdns_fqdns.txt"
  else
    warn "Skipping altdns (missing wordlist or labels)"
    : > "$BASE_DIR/permutations/altdns_fqdns.txt"
  fi

  # Combine all permutations and filter valid patterns
  {
    [[ -s "$BASE_DIR/permutations/dnsgen_raw.txt" ]] && cat "$BASE_DIR/permutations/dnsgen_raw.txt"
    [[ -s "$BASE_DIR/permutations/altdns_fqdns.txt" ]] && cat "$BASE_DIR/permutations/altdns_fqdns.txt"
  } | grep -E "\.$domain$" \
    | sort -u > "$BASE_DIR/permutations/all_permutations.txt"

  log "Permutations generated: $(wc -l < "$BASE_DIR/permutations/all_permutations.txt" 2>/dev/null || echo 0)"
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
    > "$BASE_DIR/recon_intel/cloud_assets.txt" || true

  # Subdomain takeover candidates - improved patterns
  grep -Eo '^[^ ]+' "$BASE_DIR/dns/dns_to_ip_map.txt" | grep -Eai \
    'herokuapp\.com|github\.io|s3\.amazonaws\.com|s3-website|' \
'elasticbeanstalk\.com|azurewebsites\.net|cloudapp\.azure\.com|' \
'trafficmanager\.net|blob\.core\.windows\.net|cloudapp\.net|' \
'azureedge\.net|fastly\.net|netlify\.app|vercel\.app|' \
'zendesk\.com|bitbucket\.io|ghost\.io|readme\.io|' \
'pantheonsite\.io|surge\.sh|shopify\.com|desk\.com' \
    | sort -u > "$BASE_DIR/recon_intel/takeover_candidates.txt" || true

  # Extract third-party services
  grep -Eo '^[^ ]+' "$BASE_DIR/dns/dns_to_ip_map.txt" | grep -Eai \
    'zendesk|atlassian|salesforce|shopify|wordpress|wix' \
    | sort -u > "$BASE_DIR/recon_intel/third_party_services.txt" || true

  # Identify wildcards (multiple subdomains pointing to same IP)
  awk '{print $2}' "$BASE_DIR/dns/dns_to_ip_map.txt" | sort | uniq -c | sort -rn \
    | awk '$1 > 5 {print $2}' \
    > "$BASE_DIR/recon_intel/potential_wildcards.txt" || true

  log "Cloud assets: $(wc -l < "$BASE_DIR/recon_intel/cloud_assets.txt" 2>/dev/null || echo 0)"
  log "Takeover candidates: $(wc -l < "$BASE_DIR/recon_intel/takeover_candidates.txt" 2>/dev/null || echo 0)"
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
  grep '\[200\]' "$BASE_DIR/http_discovery/httpx_full.txt" | awk '{print $1}' \
    > "$BASE_DIR/http_discovery/status_200.txt" || true
  
  grep '\[403\]' "$BASE_DIR/http_discovery/httpx_full.txt" | awk '{print $1}' \
    > "$BASE_DIR/http_discovery/status_403.txt" || true

  grep '\[401\]' "$BASE_DIR/http_discovery/httpx_full.txt" | awk '{print $1}' \
    > "$BASE_DIR/http_discovery/status_401.txt" || true

  # Extract technologies
  grep -oP '\[.*?\]' "$BASE_DIR/http_discovery/httpx_full.txt" | sort -u \
    > "$BASE_DIR/http_discovery/technologies.txt" || true

  log "Live HTTP services: $(wc -l < "$BASE_DIR/http_discovery/live_urls.txt" 2>/dev/null || echo 0)"
fi

########################################
# HTTP EXPLOITATION
########################################
if should_run http_exploitation; then
  log "STAGE: http_exploitation"

  # High-value endpoints
  grep -Eai '(admin|api|auth|login|dashboard|panel|console|vpn|portal|staging|dev|test)' \
    "$BASE_DIR/http_discovery/live_urls.txt" \
    | sort -u > "$BASE_DIR/http_exploitation/high_value_urls.txt" || true

  # Authenticated endpoints (401/403)
  safe_cat "$BASE_DIR/http_discovery/status_401.txt" \
           "$BASE_DIR/http_discovery/status_403.txt" \
    | sort -u > "$BASE_DIR/http_exploitation/auth_required.txt" || true

  log "High-value URLs: $(wc -l < "$BASE_DIR/http_exploitation/high_value_urls.txt" 2>/dev/null || echo 0)"
fi

########################################
# NUCLEI
########################################
if should_run nuclei; then
  log "STAGE: nuclei"

  # Update templates first
  log "Updating Nuclei templates..."
  nuclei -update-templates -silent 2>/dev/null || true

  # Subdomain takeover scan - HIGH PRIORITY
  if [[ -s "$BASE_DIR/recon_intel/takeover_candidates.txt" ]]; then
    log "Scanning for subdomain takeovers..."
    nuclei -l "$BASE_DIR/recon_intel/takeover_candidates.txt" \
           -t "$NUCLEI_TEMPLATES/http/takeovers/" \
           -t "$NUCLEI_TEMPLATES/dns/azure-takeover-detection.yaml" \
           -t "$NUCLEI_TEMPLATES/dns/elasticbeanstalk-takeover.yaml" \
           -severity info,low,medium,high,critical \
           -c "$NUCLEI_CONCURRENCY" \
           -rl "$NUCLEI_RATE" \
           -silent -no-color \
           -markdown-export "$BASE_DIR/nuclei/takeovers.md" \
           -json-export "$BASE_DIR/nuclei/takeovers.json" \
           -o "$BASE_DIR/nuclei/takeovers.txt" || true
  fi

  # CVE and vulnerability scan on high-value targets
  if [[ -s "$BASE_DIR/http_exploitation/high_value_urls.txt" ]]; then
    log "Scanning high-value URLs for CVEs and vulnerabilities..."
    nuclei -l "$BASE_DIR/http_exploitation/high_value_urls.txt" \
           -t "$NUCLEI_TEMPLATES/cves/" \
           -t "$NUCLEI_TEMPLATES/vulnerabilities/" \
           -t "$NUCLEI_TEMPLATES/exposures/" \
           -t "$NUCLEI_TEMPLATES/misconfiguration/" \
           -severity high,critical \
           -c "$NUCLEI_CONCURRENCY" \
           -rl "$NUCLEI_RATE" \
           -silent -no-color \
           -markdown-export "$BASE_DIR/nuclei/high_value.md" \
           -json-export "$BASE_DIR/nuclei/high_value.json" \
           -o "$BASE_DIR/nuclei/high_value_findings.txt" || true
  fi

  # Exposed panels and login pages
  if [[ -s "$BASE_DIR/http_discovery/live_urls.txt" ]]; then
    log "Scanning for exposed panels and authentication pages..."
    nuclei -l "$BASE_DIR/http_discovery/live_urls.txt" \
           -t "$NUCLEI_TEMPLATES/exposed-panels/" \
           -t "$NUCLEI_TEMPLATES/default-logins/" \
           -severity medium,high,critical \
           -c "$NUCLEI_CONCURRENCY" \
           -rl "$NUCLEI_RATE" \
           -silent -no-color \
           -o "$BASE_DIR/nuclei/exposed_panels.txt" || true
  fi

  # Technologies and misconfigurations scan
  if [[ -s "$BASE_DIR/http_discovery/live_urls.txt" ]]; then
    log "Scanning for misconfigurations and exposures..."
    nuclei -l "$BASE_DIR/http_discovery/live_urls.txt" \
           -t "$NUCLEI_TEMPLATES/misconfiguration/" \
           -t "$NUCLEI_TEMPLATES/exposures/" \
           -t "$NUCLEI_TEMPLATES/miscellaneous/" \
           -severity medium,high,critical \
           -c "$NUCLEI_CONCURRENCY" \
           -rl "$NUCLEI_RATE" \
           -silent -no-color \
           -exclude-tags dos,fuzz,intrusive \
           -o "$BASE_DIR/nuclei/misconfigurations.txt" || true
  fi

  # Comprehensive scan on all live URLs (if not too many)
  LIVE_COUNT=$(wc -l < "$BASE_DIR/http_discovery/live_urls.txt" 2>/dev/null || echo 0)
  if [[ "$LIVE_COUNT" -lt 500 && -s "$BASE_DIR/http_discovery/live_urls.txt" ]]; then
    log "Running comprehensive Nuclei scan on all $LIVE_COUNT live URLs..."
    nuclei -l "$BASE_DIR/http_discovery/live_urls.txt" \
           -severity low,medium,high,critical \
           -c "$NUCLEI_CONCURRENCY" \
           -rl "$NUCLEI_RATE" \
           -silent -no-color \
           -exclude-tags dos,fuzz,intrusive \
           -exclude-severity info \
           -markdown-export "$BASE_DIR/nuclei/comprehensive.md" \
           -json-export "$BASE_DIR/nuclei/comprehensive.json" \
           -o "$BASE_DIR/nuclei/all_findings.txt" || true
  else
    log "Skipping comprehensive scan: $LIVE_COUNT URLs (threshold: 500)"
  fi

  # Combine all critical findings
  log "Aggregating critical findings..."
  {
    [[ -s "$BASE_DIR/nuclei/takeovers.txt" ]] && grep -i 'critical\|high' "$BASE_DIR/nuclei/takeovers.txt"
    [[ -s "$BASE_DIR/nuclei/high_value_findings.txt" ]] && grep -i 'critical\|high' "$BASE_DIR/nuclei/high_value_findings.txt"
    [[ -s "$BASE_DIR/nuclei/misconfigurations.txt" ]] && grep -i 'critical' "$BASE_DIR/nuclei/misconfigurations.txt"
  } 2>/dev/null | sort -u > "$BASE_DIR/nuclei/CRITICAL_FINDINGS.txt" || true

  log "Nuclei scans completed"
  log "Critical findings: $(wc -l < "$BASE_DIR/nuclei/CRITICAL_FINDINGS.txt" 2>/dev/null || echo 0)"
fi

########################################
# FINAL SUMMARY
########################################
log "================================================"
log "Recon Summary for $domain"
log "================================================"
log "Passive seeds: $(wc -l < "$BASE_DIR/passive/passive_seeds.txt" 2>/dev/null || echo 0)"
log "Resolved domains: $(wc -l < "$BASE_DIR/dns/resolved_domains.txt" 2>/dev/null || echo 0)"
log "Live HTTP services: $(wc -l < "$BASE_DIR/http_discovery/live_urls.txt" 2>/dev/null || echo 0)"
log "Takeover candidates: $(wc -l < "$BASE_DIR/recon_intel/takeover_candidates.txt" 2>/dev/null || echo 0)"
log "High-value URLs: $(wc -l < "$BASE_DIR/http_exploitation/high_value_urls.txt" 2>/dev/null || echo 0)"
log "CRITICAL Nuclei findings: $(wc -l < "$BASE_DIR/nuclei/CRITICAL_FINDINGS.txt" 2>/dev/null || echo 0)"
log "================================================"

echo ""
echo "[✓] Recon completed for $domain"
echo "    Results: $BASE_DIR"
echo ""
echo "Key Files:"
echo "  - Domains:  $BASE_DIR/dns/resolved_domains.txt"
echo "  - Live URLs: $BASE_DIR/http_discovery/live_urls.txt"
echo "  - Takeovers: $BASE_DIR/recon_intel/takeover_candidates.txt"
echo "  - CRITICAL:  $BASE_DIR/nuclei/CRITICAL_FINDINGS.txt"
echo ""
