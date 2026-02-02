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
# Uninstall Go-based tools
########################################
uninstall_subfinder() {
    log "Uninstalling subfinder..."
    if command -v subfinder &>/dev/null; then
        go clean -i github.com/projectdiscovery/subfinder/v2/cmd/subfinder
        success "subfinder uninstalled"
    else
        warn "subfinder not found"
    fi
}

uninstall_assetfinder() {
    log "Uninstalling assetfinder..."
    if command -v assetfinder &>/dev/null; then
        go clean -i github.com/tomnomnom/assetfinder
        success "assetfinder uninstalled"
    else
        warn "assetfinder not found"
    fi
}

uninstall_puredns() {
    log "Uninstalling puredns..."
    if command -v puredns &>/dev/null; then
        go clean -i github.com/d3mondev/puredns/v2
        success "puredns uninstalled"
    else
        warn "puredns not found"
    fi
}

uninstall_httpx() {
    log "Uninstalling httpx..."
    if command -v httpx &>/dev/null; then
        go clean -i github.com/projectdiscovery/httpx/cmd/httpx
        success "httpx uninstalled"
    else
        warn "httpx not found"
    fi
}

uninstall_nuclei() {
    log "Uninstalling nuclei..."
    if command -v nuclei &>/dev/null; then
        go clean -i github.com/projectdiscovery/nuclei/v3/cmd/nuclei
        success "nuclei uninstalled"
    else
        warn "nuclei not found"
    fi
}

########################################
# Uninstall Python-based tools
########################################
uninstall_dnsgen() {
    log "Uninstalling dnsgen..."
    if command -v dnsgen &>/dev/null; then
        python3 -m pip uninstall -y dnsgen
        success "dnsgen uninstalled"
    else
        warn "dnsgen not found"
    fi
}

uninstall_altdns() {
    log "Uninstalling altdns..."
    if command -v altdns &>/dev/null; then
        pip3 uninstall -y py-altdns
        success "altdns uninstalled"
    else
        warn "altdns not found"
    fi
}

########################################
# Uninstall system packages
########################################
uninstall_amass() {
    log "Uninstalling amass..."
    if command -v amass &>/dev/null; then
        if command -v apt-get &>/dev/null; then
            sudo apt-get remove -y amass
        elif command -v yum &>/dev/null; then
            sudo yum remove -y amass
        elif command -v brew &>/dev/null; then
            brew uninstall amass
        else
            go clean -i github.com/owasp-amass/amass/v4
        fi
        success "amass uninstalled"
    else
        warn "amass not found"
    fi
}

########################################
# Remove configuration and wordlists
########################################
remove_wordlists() {
    log "Removing wordlists and resolvers..."
    
    WORDLIST_DIR="$HOME/wordlists"
    RESOLVERS_FILE="$HOME/resolvers.txt"
    AMASS_DIR="$HOME/.config/amass"
    
    if [[ -d "$WORDLIST_DIR" ]]; then
        rm -rf "$WORDLIST_DIR"
        success "Wordlist directory removed: $WORDLIST_DIR"
    else
        warn "Wordlist directory not found"
    fi
    
    if [[ -f "$RESOLVERS_FILE" ]]; then
        rm -f "$RESOLVERS_FILE"
        success "Resolvers file removed: $RESOLVERS_FILE"
    else
        warn "Resolvers file not found"
    fi
    
    if [[ -d "$AMASS_DIR" ]]; then
        rm -rf "$AMASS_DIR"
        success "Amass configuration removed: $AMASS_DIR"
    else
        warn "Amass configuration not found"
    fi
}

########################################
# Main uninstallation
########################################
main() {
    echo ""
    log "========================================"
    log "Recon Tools Uninstallation Script"
    log "========================================"
    echo ""
    
    # Uninstall Go tools
    uninstall_subfinder
    uninstall_assetfinder
    uninstall_puredns
    uninstall_httpx
    uninstall_nuclei
    
    # Uninstall Python tools
    uninstall_dnsgen
    uninstall_altdns
    
    # Uninstall system packages
    uninstall_amass
    
    # Remove wordlists and configuration files
    remove_wordlists
    
    echo ""
    log "========================================"
    log "Uninstallation Complete"
    log "========================================"
    echo ""
    success "All selected tools and configurations have been removed!"
}

main "$@"
