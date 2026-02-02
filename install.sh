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
# Check prerequisites
########################################
check_prerequisites() {
    log "Checking prerequisites..."

    # Check Go
    if ! command -v go &>/dev/null; then
        error "Go is not installed. Please install Go 1.21+ first:"
        echo "  wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz"
        echo "  sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz"
        echo "  echo 'export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin' >> ~/.bashrc"
        echo "  source ~/.bashrc"
        exit 1
    fi
    success "Go found: $(go version)"

    # Check Python3
    if ! command -v python3 &>/dev/null; then
        error "Python3 is not installed. Please install Python3 first:"
        echo "  sudo apt-get update && sudo apt-get install -y python3 python3-pip"
        exit 1
    fi
    success "Python3 found: $(python3 --version)"

    # Check pip3
    if ! command -v pip3 &>/dev/null; then
        warn "pip3 not found, installing..."
        sudo apt-get update && sudo apt-get install -y python3-pip
    fi
    success "pip3 found"

    # Ensure Go bin is in PATH
    export PATH=$PATH:$(go env GOPATH)/bin
    grep -qxF 'export PATH=$PATH:$(go env GOPATH)/bin' ~/.bashrc || \
        echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
}

########################################
# Install Go-based tools
########################################
install_subfinder() {
    log "Installing subfinder..."
    if command -v subfinder &>/dev/null; then
        success "subfinder already installed: $(subfinder -version 2>&1 | head -n1)"
    else
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        command -v subfinder &>/dev/null && success "subfinder installed" || error "subfinder installation failed"
    fi
}

install_assetfinder() {
    log "Installing assetfinder..."
    if command -v assetfinder &>/dev/null; then
        success "assetfinder already installed"
    else
        go install -v github.com/tomnomnom/assetfinder@latest
        command -v assetfinder &>/dev/null && success "assetfinder installed" || error "assetfinder installation failed"
    fi
}

install_puredns() {
    log "Installing puredns..."
    if command -v puredns &>/dev/null; then
        success "puredns already installed: $(puredns version 2>&1 || echo 'installed')"
    else
        go install github.com/d3mondev/puredns/v2@latest
        command -v puredns &>/dev/null && success "puredns installed" || error "puredns installation failed"
    fi
}

install_httpx() {
    log "Installing httpx..."
    if command -v httpx &>/dev/null; then
        success "httpx already installed: $(httpx -version 2>&1 | head -n1)"
    else
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
        command -v httpx &>/dev/null && success "httpx installed" || error "httpx installation failed"
    fi
}

install_nuclei() {
    log "Installing nuclei..."
    if command -v nuclei &>/dev/null; then
        success "nuclei already installed: $(nuclei -version 2>&1 | head -n1)"
    else
        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
        command -v nuclei &>/dev/null && {
            success "nuclei installed"
            log "Downloading nuclei templates..."
            nuclei -update-templates -silent
        } || error "nuclei installation failed"
    fi
}

########################################
# Install Python-based tools
########################################
install_dnsgen() {
    log "Installing dnsgen..."
    if command -v dnsgen &>/dev/null; then
        success "dnsgen already installed"
    else
        python3 -m pip install dnsgen --break-system-packages || python3 -m pip install dnsgen
        command -v dnsgen &>/dev/null && success "dnsgen installed" || error "dnsgen installation failed"
    fi
}

install_altdns() {
    log "Installing altdns..."
    if command -v altdns &>/dev/null; then
        success "altdns already installed"
    else
        pip3 install py-altdns==1.0.2 --break-system-packages || pip3 install py-altdns==1.0.2
        command -v altdns &>/dev/null && success "altdns installed" || error "altdns installation failed"
    fi
}

########################################
# Install system packages
########################################
install_amass() {
    log "Installing amass..."
    if command -v amass &>/dev/null; then
        success "amass already installed: $(amass -version 2>&1 | head -n1)"
    else
        sudo apt-get update
        sudo apt-get install -y amass || warn "Install from source if needed"
        command -v amass &>/dev/null && success "amass installed" || error "amass installation failed"
    fi
}

install_massdns() {
    log "Installing massdns..."
    if command -v massdns &>/dev/null; then
        success "massdns already installed"
        return 0
    fi

    if command -v apt-get &>/dev/null; then
        sudo apt-get update
        sudo apt-get install -y massdns
    else
        warn "apt-get not found, installing massdns from source..."
        git clone https://github.com/blechschmidt/massdns.git /tmp/massdns
        (cd /tmp/massdns && make)
        sudo cp /tmp/massdns/bin/massdns /usr/local/bin/
    fi

    command -v massdns &>/dev/null && success "massdns installed" || error "massdns installation failed"
}

########################################
# Download wordlists and resolvers
########################################
setup_wordlists() {
    log "Setting up wordlists and resolvers..."

    WORDLIST_DIR="$HOME/wordlists"
    RESOLVERS_FILE="$HOME/resolvers.txt"

    mkdir -p "$WORDLIST_DIR"

    # DNS wordlist
    [[ -f "$WORDLIST_DIR/dns.txt" ]] || wget -q -O "$WORDLIST_DIR/dns.txt" \
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt" \
        && success "DNS wordlist downloaded"

    # Altdns wordlist
    [[ -f "$WORDLIST_DIR/altdns_words.txt" ]] || wget -q -O "$WORDLIST_DIR/altdns_words.txt" \
        "https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt" \
        && success "Altdns wordlist downloaded"

    # Resolvers
    [[ -f "$RESOLVERS_FILE" ]] || wget -q -O "$RESOLVERS_FILE" \
        "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt" \
        && success "Resolvers downloaded"
}

########################################
# Setup Amass configuration
########################################
setup_amass_config() {
    log "Setting up Amass configuration..."
    AMASS_DIR="$HOME/.config/amass"
    mkdir -p "$AMASS_DIR"

    if [[ ! -f "$AMASS_DIR/config.yaml" ]]; then
        cat > "$AMASS_DIR/config.yaml" <<'EOF'
# Amass Configuration
scope:
  # domains will be added dynamically by the script

options:
  resolvers: /home/ubuntu/resolvers.txt

datasources:
  - name: AlienVault
    ttl: 4320
  - name: Censys
    ttl: 4320
  - name: CertSpotter
    ttl: 4320
  - name: Crtsh
    ttl: 4320
  - name: HackerTarget
    ttl: 4320
  - name: URLScan
    ttl: 4320
  - name: VirusTotal
    ttl: 4320
  - name: Shodan
    ttl: 4320
EOF
        success "Amass config created at $AMASS_DIR/config.yaml"
        echo "Please also modify datasources.yaml if needed and copy to $AMASS_DIR/datasources.yaml with provided yaml file"
    else
        success "Amass config already exists"
    fi
}

########################################
# Main installation
########################################
main() {
    echo ""
    log "========================================"
    log "Recon Tools Installation Script"
    log "=====================
