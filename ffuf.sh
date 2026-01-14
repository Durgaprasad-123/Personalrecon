#!/usr/bin/env bash
set -Eeuo pipefail

########################################
# Colors for output
########################################
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() { echo -e "${BLUE}[*]${NC} $*"; }
success() { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; }

########################################
# USAGE
########################################
show_help() {
cat <<EOF
Usage:
  $(basename "$0") <targets_file> [options]

Options:
  -w, --wordlist <path>    Custom wordlist (can specify multiple times)
  -t, --threads <num>      Number of threads (default: 30)
  -o, --output <dir>       Output directory (default: ffuf-results)
  --timeout <sec>          Request timeout (default: 10)
  --max-targets <num>      Maximum targets to scan (default: 100)
  -h, --help               Show this help

Examples:
  $(basename "$0") httpx_full.txt
  $(basename "$0") httpx_full.txt -w /path/to/custom.txt
  $(basename "$0") httpx_full.txt --threads 50 --max-targets 50

Default wordlists used if none specified:
  - raft-small-directories.txt
  - raft-medium-directories.txt
  - api-endpoints.txt
EOF
}

########################################
# ARGUMENTS
########################################
if [ $# -lt 1 ]; then
  show_help
  exit 1
fi

TARGETS_FILE="$1"
shift

USER_WORDLISTS=()
THREADS=30
TIMEOUT=10
MAX_TARGETS=100
OUTPUT_DIR="ffuf-results"
USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    -w|--wordlist)
      USER_WORDLISTS+=("$2")
      shift 2
      ;;
    -t|--threads)
      THREADS="$2"
      shift 2
      ;;
    -o|--output)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --timeout)
      TIMEOUT="$2"
      shift 2
      ;;
    --max-targets)
      MAX_TARGETS="$2"
      shift 2
      ;;
    -h|--help)
      show_help
      exit 0
      ;;
    *)
      warn "Unknown option: $1"
      show_help
      exit 1
      ;;
  esac
done

########################################
# Default curated wordlists
########################################
DEFAULT_WORDLISTS=(
  "/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-directories.txt"
  "/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt"
  "/usr/share/wordlists/SecLists/Discovery/Web-Content/api/api-endpoints.txt"
  "/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt"
)

########################################
# Alternative wordlist locations
########################################
ALTERNATIVE_LOCATIONS=(
  "$HOME/wordlists/SecLists/Discovery/Web-Content"
  "$HOME/SecLists/Discovery/Web-Content"
  "/opt/SecLists/Discovery/Web-Content"
)

########################################
# CHECK FFUF
########################################
if ! command -v ffuf &>/dev/null; then
  error "ffuf is not installed"
  echo ""
  echo "Install ffuf using:"
  echo "  go install github.com/ffuf/ffuf/v2@latest"
  echo ""
  exit 1
fi

########################################
# CHECK TARGET FILE
########################################
if [ ! -f "$TARGETS_FILE" ]; then
  error "Targets file not found: $TARGETS_FILE"
  exit 1
fi

# Count targets
TARGET_COUNT=$(awk '{print $1}' "$TARGETS_FILE" 2>/dev/null | grep -E '^https?://' | wc -l || echo 0)

if [ "$TARGET_COUNT" -eq 0 ]; then
  error "No valid URLs found in $TARGETS_FILE"
  echo "Expected format: URL [status] [title] [tech]"
  exit 1
fi

log "Found $TARGET_COUNT targets in $TARGETS_FILE"

# Limit targets if too many
if [ "$TARGET_COUNT" -gt "$MAX_TARGETS" ]; then
  warn "Target count ($TARGET_COUNT) exceeds max ($MAX_TARGETS)"
  warn "Will scan first $MAX_TARGETS targets only"
fi

########################################
# WORDLIST SELECTION
########################################
if [ ${#USER_WORDLISTS[@]} -gt 0 ]; then
  WORDLISTS=("${USER_WORDLISTS[@]}")
  log "Using ${#WORDLISTS[@]} user-provided wordlist(s)"
else
  # Try to find default wordlists
  FOUND_WORDLISTS=()
  
  for WL in "${DEFAULT_WORDLISTS[@]}"; do
    if [ -f "$WL" ]; then
      FOUND_WORDLISTS+=("$WL")
    else
      # Try alternative locations
      WL_BASENAME=$(basename "$WL")
      FOUND_ALT=false
      
      for ALT_DIR in "${ALTERNATIVE_LOCATIONS[@]}"; do
        if [ -f "$ALT_DIR/$WL_BASENAME" ]; then
          FOUND_WORDLISTS+=("$ALT_DIR/$WL_BASENAME")
          FOUND_ALT=true
          break
        fi
      done
      
      if [ "$FOUND_ALT" = false ]; then
        warn "Wordlist not found: $WL_BASENAME"
      fi
    fi
  done
  
  if [ ${#FOUND_WORDLISTS[@]} -eq 0 ]; then
    error "No wordlists found"
    echo ""
    echo "Install SecLists using:"
    echo "  sudo apt update && sudo apt install seclists"
    echo ""
    echo "OR manually:"
    echo "  git clone https://github.com/danielmiessler/SecLists.git ~/wordlists/SecLists"
    echo ""
    echo "OR provide custom wordlists:"
    echo "  $(basename "$0") $TARGETS_FILE -w /path/to/wordlist.txt"
    echo ""
    exit 1
  fi
  
  WORDLISTS=("${FOUND_WORDLISTS[@]}")
  log "Using ${#WORDLISTS[@]} default wordlist(s)"
fi

########################################
# WORDLIST VALIDATION
########################################
for WL in "${WORDLISTS[@]}"; do
  if [ ! -f "$WL" ]; then
    error "Wordlist not found: $WL"
    exit 1
  fi
  WL_SIZE=$(wc -l < "$WL" 2>/dev/null || echo 0)
  log "  - $(basename "$WL"): $WL_SIZE words"
done

########################################
# PREPARE OUTPUT
########################################
mkdir -p "$OUTPUT_DIR"
SUMMARY_FILE="$OUTPUT_DIR/scan_summary.txt"
: > "$SUMMARY_FILE"

########################################
# START SCANNING
########################################
echo ""
log "========================================="
log "Starting ffuf directory fuzzing"
log "========================================="
log "Targets: $TARGET_COUNT (max: $MAX_TARGETS)"
log "Threads: $THREADS"
log "Timeout: ${TIMEOUT}s"
log "Output: $OUTPUT_DIR"
echo ""

SCANNED_COUNT=0
TOTAL_FINDINGS=0

# Extract and scan URLs
awk '{print $1}' "$TARGETS_FILE" | grep -E '^https?://' | sort -u | head -n "$MAX_TARGETS" | while read -r URL; do
  ((SCANNED_COUNT++)) || true
  
  # Create safe directory name
  DOMAIN=$(echo "$URL" | sed -e 's|https\?://||g' -e 's|[/:]|_|g' -e 's|_$||')
  DOMAIN_DIR="$OUTPUT_DIR/$DOMAIN"
  mkdir -p "$DOMAIN_DIR"
  
  log "[$SCANNED_COUNT/$MAX_TARGETS] Scanning: $URL"
  
  DOMAIN_FINDINGS=0
  
  for WORDLIST in "${WORDLISTS[@]}"; do
    WL_NAME=$(basename "$WORDLIST" .txt)
    OUTPUT_FILE="$DOMAIN_DIR/${WL_NAME}.json"
    
    echo "    [+] Wordlist: $WL_NAME"
    
    # Run ffuf with progress
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
      -s 2>/dev/null || true
    
    # Count findings
    if [ -f "$OUTPUT_FILE" ]; then
      FINDINGS=$(jq -r '.results | length' "$OUTPUT_FILE" 2>/dev/null || echo 0)
      if [ "$FINDINGS" -gt 0 ]; then
        echo "        → Found $FINDINGS paths"
        ((DOMAIN_FINDINGS+=FINDINGS)) || true
        ((TOTAL_FINDINGS+=FINDINGS)) || true
        
        # Extract interesting findings
        jq -r '.results[] | "\(.status) \(.url)"' "$OUTPUT_FILE" 2>/dev/null \
          >> "$DOMAIN_DIR/all_findings.txt" || true
      else
        # Remove empty JSON files
        rm -f "$OUTPUT_FILE"
      fi
    fi
  done
  
  # Summary for this domain
  if [ "$DOMAIN_FINDINGS" -gt 0 ]; then
    echo "$URL: $DOMAIN_FINDINGS findings" >> "$SUMMARY_FILE"
    success "Found $DOMAIN_FINDINGS total paths for $URL"
  else
    echo "    → No findings"
  fi

  # If the domain directory contains no non-empty files, remove it to avoid clutter
  # (this helps when a target produced no findings or only zero-byte files)
  if ! find "$DOMAIN_DIR" -type f -not -size 0 -print -quit >/dev/null 2>&1; then
    warn "No non-empty result files for $URL — removing $DOMAIN_DIR"
    rm -rf "$DOMAIN_DIR" 2>/dev/null || true
  fi
  
  echo ""
done

########################################
# CLEANUP & SUMMARY
########################################
log "Cleaning up empty files..."
find "$OUTPUT_DIR" -type f -empty -delete 2>/dev/null || true
find "$OUTPUT_DIR" -type d -empty -delete 2>/dev/null || true

echo ""
log "========================================="
log "Scan Summary"
log "========================================="
log "Total findings: $TOTAL_FINDINGS"
log "Results saved to: $OUTPUT_DIR"

if [ -s "$SUMMARY_FILE" ]; then
  echo ""
  log "Findings by target:"
  cat "$SUMMARY_FILE" | head -20
  
  if [ $(wc -l < "$SUMMARY_FILE") -gt 20 ]; then
    echo "    ... (see $SUMMARY_FILE for full list)"
  fi
fi

echo ""
success "ffuf scanning completed"
echo ""

# Create aggregated results
if [ "$TOTAL_FINDINGS" -gt 0 ]; then
  log "Creating aggregated results..."
  
  # All findings sorted by URL (primary) then by status (numeric)
  find "$OUTPUT_DIR" -name "all_findings.txt" -exec cat {} \; 2>/dev/null \
    | sort -t' ' -k2,2 -k1,1n | uniq > "$OUTPUT_DIR/ALL_FINDINGS.txt" || true
  
  # Extract high-value findings (status at start of line)
  grep -E '^(200|500|403|401) ' "$OUTPUT_DIR/ALL_FINDINGS.txt" 2>/dev/null \
    | sort -u > "$OUTPUT_DIR/HIGH_VALUE_FINDINGS.txt" || true
  
  log "Key files:"
  log "  - All findings: $OUTPUT_DIR/ALL_FINDINGS.txt"
  log "  - High-value: $OUTPUT_DIR/HIGH_VALUE_FINDINGS.txt"
fi

echo ""
