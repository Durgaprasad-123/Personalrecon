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
        if command -v subfinder &>/dev/null; then
            success "subfinder installed: $(subfinder -version 2>&1 | head -n1)"
        else
            error "subfinder installation failed"
            return 1
        fi
    fi
}

install_assetfinder() {
    log "Installing assetfinder..."
    if command -v assetfinder &>/dev/null; then
        success "assetfinder already installed"
    else
        go install -v github.com/tomnomnom/assetfinder@latest
        if command -v assetfinder &>/dev/null; then
            success "assetfinder installed"
        else
            error "assetfinder installation failed"
            return 1
        fi
    fi
}

install_puredns() {
    log "Installing puredns..."
    if command -v puredns &>/dev/null; then
        success "puredns already installed: $(puredns version 2>&1 || echo 'installed')"
    else
        go install github.com/d3mondev/puredns/v2@latest
        if command -v puredns &>/dev/null; then
            success "puredns installed: $(puredns version 2>&1 || echo 'installed')"
        else
            error "puredns installation failed"
            return 1
        fi
    fi
}

install_httpx() {
    log "Installing httpx..."
    if command -v httpx &>/dev/null; then
        success "httpx already installed: $(httpx -version 2>&1 | head -n1)"
    else
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
        if command -v httpx &>/dev/null; then
            success "httpx installed: $(httpx -version 2>&1 | head -n1)"
        else
            error "httpx installation failed"
            return 1
        fi
    fi
}

install_nuclei() {
    log "Installing nuclei..."
    if command -v nuclei &>/dev/null; then
        success "nuclei already installed: $(nuclei -version 2>&1 | head -n1)"
    else
        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
        if command -v nuclei &>/dev/null; then
            success "nuclei installed: $(nuclei -version 2>&1 | head -n1)"
            log "Downloading nuclei templates..."
            nuclei -update-templates -silent
            success "Nuclei templates downloaded"
        else
            error "nuclei installation failed"
            return 1
        fi
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
        python3 -m pip install dnsgen --break-system-packages 2>/dev/null || python3 -m pip install dnsgen
        if command -v dnsgen &>/dev/null; then
            success "dnsgen installed"
        else
            error "dnsgen installation failed"
            return 1
        fi
    fi
}

install_altdns() {
    log "Installing altdns..."
    if command -v altdns &>/dev/null; then
        success "altdns already installed"
    else
        pip3 install py-altdns==1.0.2 --break-system-packages 2>/dev/null || pip3 install py-altdns==1.0.2
        if command -v altdns &>/dev/null; then
            success "altdns installed"
        else
            error "altdns installation failed"
            return 1
        fi
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
        if command -v apt-get &>/dev/null; then
            sudo apt-get update
            sudo apt-get install -y amass
        elif command -v yum &>/dev/null; then
            sudo yum install -y amass
        elif command -v brew &>/dev/null; then
            brew install amass
        else
            warn "Package manager not found. Installing from source..."
            go install -v github.com/owasp-amass/amass/v4/...@master
        fi
        if command -v amass &>/dev/null; then
            success "amass installed: $(amass -version 2>&1 | head -n1)"
        else
            error "amass installation failed"
            return 1
        fi
    fi
}

########################################
# Download wordlists and resolvers
########################################
setup_wordlists() {
    log "Setting up wordlists and resolvers..."
    
    WORDLIST_DIR="$HOME/wordlists"
    RESOLVERS_FILE="$HOME/resolvers.txt"
    
    mkdir -p "$WORDLIST_DIR"
    
    # Download DNS wordlist if not exists
    if [[ ! -f "$WORDLIST_DIR/dns.txt" ]]; then
        log "Downloading DNS wordlist..."
        wget -q -O "$WORDLIST_DIR/dns.txt" \
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt" || \
        wget -q -O "$WORDLIST_DIR/dns.txt" \
            "https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt"
        success "DNS wordlist downloaded: $WORDLIST_DIR/dns.txt"
    else
        success "DNS wordlist already exists: $WORDLIST_DIR/dns.txt"
    fi
    
    # Download altdns wordlist if not exists
    if [[ ! -f "$WORDLIST_DIR/altdns_words.txt" ]]; then
        log "Downloading altdns wordlist..."
        wget -q -O "$WORDLIST_DIR/altdns_words.txt" \
            "https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt"
        success "Altdns wordlist downloaded: $WORDLIST_DIR/altdns_words.txt"
    else
        success "Altdns wordlist already exists: $WORDLIST_DIR/altdns_words.txt"
    fi
    
    # Download resolvers if not exists
    if [[ ! -f "$RESOLVERS_FILE" ]]; then
        log "Downloading trusted DNS resolvers..."
        wget -q -O "$RESOLVERS_FILE" \
            "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt"
        success "Resolvers downloaded: $RESOLVERS_FILE"
    else
        success "Resolvers already exist: $RESOLVERS_FILE"
    fi
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
# Amass Configuration File
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
        success "Amass config created: $AMASS_DIR/config.yaml"
    else
        success "Amass config already exists: $AMASS_DIR/config.yaml"
    fi
}

########################################
# Main installation
########################################
main() {
    echo ""
    log "========================================"
    log "Recon Tools Installation Script"
    log "========================================"
    echo ""
    
    check_prerequisites
    echo ""
    
    # Track failures
    FAILED_TOOLS=()
    
    # Install Go tools
    install_subfinder || FAILED_TOOLS+=("subfinder")
    install_assetfinder || FAILED_TOOLS+=("assetfinder")
    install_puredns || FAILED_TOOLS+=("puredns")
    install_httpx || FAILED_TOOLS+=("httpx")
    install_nuclei || FAILED_TOOLS+=("nuclei")
    
    # Install Python tools
    install_dnsgen || FAILED_TOOLS+=("dnsgen")
    install_altdns || FAILED_TOOLS+=("altdns")
    
    # Install system packages
    install_amass || FAILED_TOOLS+=("amass")
    
    # Setup wordlists and config
    setup_wordlists
    setup_amass_config
    
    echo ""
    log "========================================"
    log "Installation Summary"
    log "========================================"
    
    if [[ ${#FAILED_TOOLS[@]} -eq 0 ]]; then
        success "All tools installed successfully!"
    else
        error "The following tools failed to install:"
        for tool in "${FAILED_TOOLS[@]}"; do
            echo "  - $tool"
        done
        echo ""
        warn "Please install failed tools manually"
    fi
    
    echo ""
    log "Run './check_tools.sh' to verify all tools are working"
    echo ""
}

main "$@"
