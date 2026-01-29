- **Note**:This Framework is still is on-progress State
# 🔍 Advanced Reconnaissance Toolkit

A comprehensive, automated reconnaissance pipeline for subdomain enumeration, vulnerability scanning, and directory fuzzing.

## 📋 Features

- **Passive Enumeration**: Subfinder, Assetfinder, Amass
- **DNS Bruteforce**: Puredns with wildcard filtering
- **Permutation Generation**: Dnsgen, Altdns
- **DNS Resolution**: Mass DNS resolution with validation
- **Intelligence Gathering**: Cloud assets, takeover candidates, third-party services
- **HTTP Discovery**: httpx with technology detection
- **Vulnerability Scanning**: Nuclei with organized template scanning
- **Directory Fuzzing**: ffuf with curated wordlists
- **Automated Cleanup**: Removes empty files and invalid results

## 🚀 Quick Start

### 1. Install Tools

```bash
# Make scripts executable
chmod +x install.sh check_tools.sh recon.sh ffuf.sh

# Install all required tools
./install.sh
```

### 2. Verify Installation

```bash
# Check all tools are working
./check_tools.sh
```

### 3. Run Reconnaissance

```bash
# Full reconnaissance pipeline
./recon.sh example.com

# Start from specific stage
./recon.sh example.com --from nuclei

# Custom output directory
./recon.sh example.com --base-dir /path/to/output
```

## 📁 Project Structure

```
recon-toolkit/
├── install.sh          # Tool installation script
├── check_tools.sh      # Verify tool installation
├── recon.sh           # Main reconnaissance script
├── ffuf.sh            # Directory fuzzing script
└── output/
    └── example.com/
        ├── passive/           # Passive enumeration results
        ├── bruteforce/        # DNS bruteforce results
        ├── permutations/      # Domain permutations
        ├── dns/              # Resolved domains and IPs
        ├── recon_intel/      # Intelligence gathering
        ├── http_discovery/   # HTTP service discovery
        ├── http_exploitation/# High-value targets
        ├── nuclei/           # Vulnerability scan results
        ├── ffuf/             # Directory fuzzing results
        └── logs/             # Execution logs
```

## 🎯 Reconnaissance Stages

### Stage 1: Passive Enumeration
- Subfinder (all sources)
- Assetfinder
- Amass (passive mode with configuration)
- Combines and deduplicates results

### Stage 2: DNS Bruteforce
- Puredns bruteforce with rate limiting
- Wildcard detection and filtering
- Combines with passive results

### Stage 3: Permutations
- Dnsgen for intelligent permutations
- Altdns for word-based variations
- Filters invalid patterns (ASN, malformed domains)

### Stage 4: DNS Resolution
- Mass DNS resolution with puredns
- Creates domain-to-IP mappings
- Extracts unique IP addresses

### Stage 5: Reconnaissance Intelligence
- Cloud asset detection (AWS, Azure, GCP, CDNs)
- Subdomain takeover candidates
- Third-party service identification
- Wildcard pattern detection

### Stage 6: HTTP Discovery
- httpx with technology detection
- Status code categorization
- Title and header extraction
- Technology fingerprinting

### Stage 7: HTTP Exploitation
- High-value endpoint identification
- Authentication-required endpoints
- Admin/API/Auth panel detection

### Stage 8: Nuclei Vulnerability Scanning
1. **Subdomain Takeover** (CRITICAL)
2. **CVE/Vulnerabilities** on high-value targets
3. **Exposed Panels** and default logins
4. **Misconfigurations** and exposures
5. **Comprehensive Scan** (if <500 targets)

### Stage 9: Directory Fuzzing (ffuf)
- Automated directory and file discovery
- Multiple curated wordlists
- Intelligent rate limiting
- Results aggregation and filtering

## 🛠️ Configuration

### Recon Script (`recon.sh`)

```bash
# HTTP scanning
HTTP_THREADS=50
HTTP_RATE=120

# Nuclei scanning
NUCLEI_CONCURRENCY=30
NUCLEI_RATE=200
NUCLEI_TIMEOUT=10

# File locations
RESOLVERS="$HOME/resolvers.txt"
WORDLIST="$HOME/wordlists/dns.txt"
ALTDNS_WORDLIST="$HOME/wordlists/altdns_words.txt"
```

### ffuf Script (`ffuf.sh`)

```bash
# Default settings
THREADS=30
TIMEOUT=10
MAX_TARGETS=100

# Custom usage
./ffuf.sh httpx_full.txt -w /path/to/wordlist.txt --threads 50
```

## 📊 Output Files

### Key Result Files

| File | Description |
|------|-------------|
| `dns/resolved_domains.txt` | All resolved subdomains |
| `http_discovery/live_urls.txt` | Live HTTP/HTTPS services |
| `recon_intel/takeover_candidates.txt` | Potential subdomain takeovers |
| `nuclei/CRITICAL_FINDINGS.txt` | High/Critical vulnerabilities |
| `ffuf/ALL_FINDINGS.txt` | All discovered paths |
| `ffuf/HIGH_VALUE_FINDINGS.txt` | 200/403/401/500 responses |

### Intelligence Files

- `recon_intel/cloud_assets.txt` - Cloud-hosted services
- `recon_intel/third_party_services.txt` - Third-party integrations
- `http_exploitation/high_value_urls.txt` - Admin/API endpoints
- `http_exploitation/auth_required.txt` - Protected endpoints

## 🔧 Advanced Usage

### Run Specific Stages

```bash
# Only nuclei scanning
./recon.sh example.com --from nuclei

# Only directory fuzzing
./recon.sh example.com --from ffuf
```

### Custom ffuf Scanning

```bash
# Custom wordlist
./ffuf.sh httpx_full.txt -w ~/wordlists/custom.txt

# Increase threads and targets
./ffuf.sh httpx_full.txt --threads 100 --max-targets 200

# Custom output directory
./ffuf.sh httpx_full.txt -o /tmp/ffuf-results
```

### Amass Configuration

Edit `~/.config/amass/config.yaml` to add API keys:

```yaml
datasources:
  - name: Censys
    ttl: 4320
    credentials:
      - apikey: YOUR_API_KEY
        secret: YOUR_SECRET
  
  - name: Shodan
    ttl: 4320
    credentials:
      - apikey: YOUR_API_KEY
```

## 🐛 Troubleshooting

### Tools Not Found

```bash
# Check what's missing
./check_tools.sh

# Install missing tools
./install.sh
```

### Nuclei Stuck/Hanging

The improved script includes:
- 30-minute timeout per scan type
- 10-second timeout per template
- Retry limits to prevent hanging
- Progress logging

### Empty Result Files

The script automatically:
- Deletes empty files after completion
- Validates results before creating files
- Uses `|| true` to prevent failures from creating empty files

### ffuf Not Finding Wordlists

```bash
# Install SecLists
sudo apt install seclists

# OR manual installation
git clone https://github.com/danielmiessler/SecLists.git ~/wordlists/SecLists

# OR use custom wordlists
./ffuf.sh targets.txt -w /path/to/your/wordlist.txt
```

### Dnsgen Generating Junk

The script now filters out:
- ASN announcements
- Malformed domains (with `--`, `..`, leading `.`)
- Invalid characters and patterns
- Non-domain output

## 📈 Performance Tips

### For Large Target Sets

```bash
# Limit ffuf scanning
./ffuf.sh httpx_full.txt --max-targets 50

# Use faster wordlists
./ffuf.sh httpx_full.txt -w ~/wordlists/short.txt
```

### For Better Results

1. **Add API keys** to Amass config for passive enumeration
2. **Use trusted resolvers** in `~/resolvers.txt`
3. **Run nuclei on filtered targets** (high-value URLs only)
4. **Increase threads** on powerful systems

### Resource Management

```bash
# Lower resource usage
HTTP_THREADS=20        # Reduce HTTP threads
NUCLEI_CONCURRENCY=15  # Reduce nuclei parallel scans
THREADS=20             # Reduce ffuf threads
```
### Changes you should make in nuclei 
# Small scans (<100 targets)
-concurrency 15 -max-host-error 30

# Medium scans (100-500 targets)
-concurrency 20 -max-host-error 50

# Large scans (>500 targets)
-concurrency 25 -max-host-error 100
########################################
# CONFIG
########################################
HTTP_THREADS=50
HTTP_RATE=120

# Nuclei settings - optimized for stability
NUCLEI_CONCURRENCY=20
NUCLEI_RATE=150
NUCLEI_TIMEOUT=15
NUCLEI_MAX_HOST_ERROR=50  # ← Add this
NUCLEI_RETRIES=2
## 🔐 Security Notes

- Always get **written permission** before scanning targets
- Respect **rate limits** and **robots.txt**
- Be aware of **legal implications** in your jurisdiction
- Use **responsible disclosure** for findings
- Don't scan **production systems** without authorization

## 📚 Tool Documentation

- [Subfinder](https://github.com/projectdiscovery/subfinder)
- [Puredns](https://github.com/d3mondev/puredns)
- [Httpx](https://github.com/projectdiscovery/httpx)
- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [ffuf](https://github.com/ffuf/ffuf)
- [Amass](https://github.com/owasp-amass/amass)

## 🤝 Contributing

Improvements welcome! Areas for contribution:
- Additional data sources
- Better filtering logic
- Performance optimizations
- New reconnaissance stages
- Documentation improvements

## 📝 License

This toolkit is for educational and authorized security testing only. Users are responsible for compliance with applicable laws and obtaining proper authorization.

## ✅ Checklist

Before running reconnaissance:

- [ ] Written authorization obtained
- [ ] Tools installed (`./check_tools.sh`)
- [ ] Resolvers downloaded
- [ ] Wordlists configured
- [ ] Output directory specified
- [ ] Rate limits configured appropriately
- [ ] Amass API keys added (optional)
- [ ] Legal compliance verified

## 🎓 Learning Resources

- OWASP Testing Guide
- Bug Bounty Methodology
- HackerOne Disclosure Guidelines
- Subdomain Takeover Prevention

---

**Happy Hunting! 🎯**
