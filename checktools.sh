#!/usr/bin/env bash
set -Eeo pipefail

########################################
# Colors for output
########################################
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

success() { echo -e "${GREEN}[✓]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
info() { echo -e "${BLUE}[i]${NC} $*"; }

########################################
# Tool checks
########################################
TOOLS=(
    "subfinder"
    "assetfinder"
    "amass"
    "puredns"
    "dnsgen"
    "altdns"
    "httpx"
    "nuclei"
    "ffuf"
    "awk"
    "sed"
    "grep"
    "sort"
    "cut"
    "jq"
)

MISSING_TOOLS=()
FOUND_TOOLS=()

echo ""
info "========================================"
info "Checking Recon Tools"
info "========================================"
echo ""

for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        # Try to get version info
        VERSION=""
        case "$tool" in
            subfinder|httpx|nuclei)
                VERSION=$(${tool} -version 2>&1 | head -n1 || echo "")
                ;;
            amass)
                VERSION=$(${tool} -version 2>&1 | head -n1 || echo "")
                ;;
            puredns)
                VERSION=$(${tool} -v 2>&1 || echo "installed")
                ;;
            ffuf)
                VERSION=$(${tool} -V 2>&1 | head -n1 || echo "")
                ;;
            *)
                VERSION="installed"
                ;;
        esac
        
        success "$tool: $VERSION"
        FOUND_TOOLS+=("$tool")
    else
        error "$tool: NOT FOUND"
        MISSING_TOOLS+=("$tool")
    fi
done

########################################
# File checks
########################################
echo ""
info "========================================"
info "Checking Required Files"
info "========================================"
echo ""

RESOLVERS="$HOME/resolvers.txt"
WORDLIST="$HOME/wordlists/dns.txt"
ALTDNS_WORDLIST="$HOME/wordlists/altdns_words.txt"
AMASS_CONFIG="$HOME/.config/amass/config.yaml"

check_file() {
    local file="$1"
    local name="$2"
    
    if [[ -f "$file" ]]; then
        local size=$(wc -l < "$file" 2>/dev/null || echo "0")
        success "$name: $file ($size lines)"
        return 0
    else
        error "$name: NOT FOUND at $file"
        return 1
    fi
}

FILE_CHECKS=0
check_file "$RESOLVERS" "Resolvers" || ((FILE_CHECKS++))
check_file "$WORDLIST" "DNS Wordlist" || ((FILE_CHECKS++))
check_file "$ALTDNS_WORDLIST" "Altdns Wordlist" || ((FILE_CHECKS++))

if [[ -f "$AMASS_CONFIG" ]]; then
    success "Amass Config: $AMASS_CONFIG"
else
    warn "Amass Config: NOT FOUND at $AMASS_CONFIG (will use default)"
fi

########################################
# Summary
########################################
echo ""
info "========================================"
info "Summary"
info "========================================"
echo ""

if [[ ${#MISSING_TOOLS[@]} -eq 0 && $FILE_CHECKS -eq 0 ]]; then
    success "All tools and files are ready!"
    echo ""
    info "You can now run: ./recon.sh <domain>"
    echo ""
    exit 0
else
    if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
        error "Missing tools: ${MISSING_TOOLS[*]}"
        echo ""
        warn "Run './install.sh' to install missing tools"
    fi
    
    if [[ $FILE_CHECKS -gt 0 ]]; then
        error "Missing required files"
        echo ""
        warn "Run './install.sh' to download missing files"
    fi
    echo ""
    exit 1
fi
