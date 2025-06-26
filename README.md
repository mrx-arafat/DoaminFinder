<div align="center">

# 🔍 Domain Finder v3.0

**Advanced Subdomain Discovery Tool with Multiple Techniques**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub](https://img.shields.io/badge/github-mrx--arafat-green.svg)](https://github.com/mrx-arafat)

*Discover hidden subdomains with cutting-edge techniques and comprehensive API integrations*

</div>

---

## 👨‍💻 Author

**Easin Arafat**
🌐 Website: [profile.arafatops.com](https://profile.arafatops.com)
🐙 GitHub: [mrx-arafat](https://github.com/mrx-arafat)

---

## 🚀 Features

### 🎯 Core Discovery Techniques
- ✅ **Certificate Transparency Logs** - Query CT logs from multiple sources (crt.sh, Censys)
- ✅ **DNS Brute Forcing** - High-speed DNS resolution with custom wordlists
- ✅ **SSL Certificate Analysis** - Extract subdomains from SAN fields
- ✅ **DNS Zone Transfer** - Attempt zone transfers from nameservers
- ✅ **Search Engine Dorking** - Google, Bing, DuckDuckGo queries
- ✅ **Third-party APIs** - SecurityTrails, VirusTotal, Shodan, Censys
- ✅ **GitHub Repository Scanning** - Search code repositories for subdomains
- ✅ **Passive DNS Databases** - RiskIQ PassiveTotal, AlienVault OTX
- ✅ **JavaScript Analysis** - Extract subdomains and secrets from JS files
- ✅ **Recursive Discovery** - Multi-level subdomain enumeration

### ⚡ Advanced Features
- 🔥 **Multi-threading** - Concurrent execution for maximum speed
- 🔥 **Request Caching** - Avoid duplicate API calls
- 🔥 **Rate Limiting** - Respectful API usage
- 🔥 **Wildcard Filtering** - Remove false positives
- 🔥 **DNS Verification** - Validate subdomain existence
- 🔥 **Cookie Support** - Authenticated scanning
- 🔥 **Proxy Support** - HTTP/HTTPS/SOCKS proxy configuration
- 🔥 **Custom Wordlists** - Use your own subdomain lists
- 🔥 **Multiple Output Formats** - Text, JSON, organized files
- 🔥 **Clickable Links** - Direct access to discovered subdomains

---

## 📦 Installation

### Prerequisites
```bash
# Python 3.8+ required
python --version

# Clone the repository
git clone https://github.com/mrx-arafat/domain-finder.git
cd domain-finder

# Install dependencies
pip install -r requirements.txt
```

### Quick Setup
```bash
# Copy environment template
cp .env .env.local

# Edit .env file with your API keys (optional but recommended)
nano .env

# Run your first scan
python domainFinder.py -u https://example.com
```

---

## 🔧 Configuration

### API Keys (Optional but Recommended)
Add your API keys to the `.env` file for enhanced discovery:

```bash
# SecurityTrails - https://securitytrails.com/corp/api
SECURITYTRAILS_API_KEY=your_key_here

# VirusTotal - https://www.virustotal.com/gui/my-apikey
VIRUSTOTAL_API_KEY=your_key_here

# Shodan - https://account.shodan.io/
SHODAN_API_KEY=your_key_here

# Censys - https://censys.io/account/api
CENSYS_API_ID=your_id_here
CENSYS_API_SECRET=your_secret_here

# GitHub - https://github.com/settings/tokens
GITHUB_TOKEN=your_token_here
```

---

## 🎯 Usage

### Basic Usage
```bash
# Simple subdomain enumeration
python domainFinder.py -u https://example.com

# With cookies for authenticated scanning
python domainFinder.py -u https://example.com -c "session=abc123; token=xyz789"

# High-performance scanning with more threads
python domainFinder.py -u https://example.com -t 100 --large-wordlist

# Fast scanning (skip slow techniques)
python domainFinder.py -u https://example.com --skip-github --skip-search --quiet
```

### Advanced Usage
```bash
# Recursive discovery with custom depth
python domainFinder.py -u https://example.com --recursive --depth 5

# Custom wordlist and output directory
python domainFinder.py -u https://example.com --custom-wordlist wordlists/custom.txt -o results/

# JSON output for automation
python domainFinder.py -u https://example.com --json > results.json

# Quiet mode for scripts
python domainFinder.py -u https://example.com --quiet

# Skip specific techniques for faster execution
python domainFinder.py -u https://example.com --skip-brute --skip-apis --skip-js

# Comprehensive scan with all features
python domainFinder.py -u https://example.com --recursive --large-wordlist -t 100 -o comprehensive_results/
```

### Performance Optimization
```bash
# Ultra-fast scan (essential techniques only)
python domainFinder.py -u https://example.com --skip-github --skip-search --skip-js --quiet

# Medium speed scan (skip slow techniques)
python domainFinder.py -u https://example.com --skip-github --skip-search

# Full scan with optimized settings
python domainFinder.py -u https://example.com -t 50 --large-wordlist

# API-focused scan (requires API keys)
python domainFinder.py -u https://example.com --skip-brute --skip-search --skip-github
```

### Cookie-based Authentication
```bash
# Simple cookie authentication
python domainFinder.py -u https://example.com -c "sessionid=abc123"

# Multiple cookies
python domainFinder.py -u https://example.com -c "sessionid=abc123; csrftoken=xyz789; auth=token123"

# JSON cookie format
python domainFinder.py -u https://example.com -c '{"domain": "example.com", "name": "session", "value": "abc123"}'
```

---

## 📊 Example Output

```
🔍 Domain Finder v3.0 - Enhanced Subdomain Discovery

Subdomains found (15):
----------------------------------------
api.example.com
blog.example.com
cdn.example.com
dev.example.com
docs.example.com
mail.example.com
shop.example.com
staging.example.com
test.example.com
www.example.com

🔗 Clickable Links:
----------------------------------------
https://api.example.com
https://blog.example.com
https://cdn.example.com
https://dev.example.com
https://docs.example.com
https://mail.example.com
https://shop.example.com
https://staging.example.com
https://test.example.com
https://www.example.com

✅ Results saved to results/subdomains_20250626_123456.txt
```

---

## 🛠️ Command Line Options

### Core Options
| Option | Description | Example |
|--------|-------------|---------|
| `-u, --url` | Target URL or domain (required) | `-u https://example.com` |
| `-c, --cookie` | Cookies for authenticated scanning | `-c "session=abc123"` |
| `-o, --output` | Output directory (default: results) | `-o my_results/` |
| `-t, --threads` | Number of threads (default: 50) | `-t 100` |
| `--quiet` | Suppress banner and progress messages | `--quiet` |

### Discovery Options
| Option | Description | Example |
|--------|-------------|---------|
| `--large-wordlist` | Use large wordlist for brute forcing | `--large-wordlist` |
| `--custom-wordlist` | Path to custom wordlist file | `--custom-wordlist wordlists/custom.txt` |
| `--recursive` | Enable recursive subdomain discovery | `--recursive` |
| `--depth` | Maximum recursion depth (default: 3) | `--depth 5` |

### Output Options
| Option | Description | Example |
|--------|-------------|---------|
| `--json` | Output results in JSON format | `--json` |
| `--save-results` | Save results to files | `--save-results` |

### Performance Options (Skip Techniques)
| Option | Description | Use Case |
|--------|-------------|----------|
| `--skip-brute` | Skip DNS brute forcing | Fast scan, when wordlist is slow |
| `--skip-search` | Skip search engine dorking | Avoid rate limiting |
| `--skip-apis` | Skip third-party APIs | No API keys available |
| `--skip-github` | Skip GitHub scanning | Fastest execution |
| `--skip-js` | Skip JavaScript analysis | Skip slow JS parsing |

### Quick Command Examples
```bash
# Ultra-fast scan
python domainFinder.py -u https://example.com --skip-github --skip-search --quiet

# Comprehensive scan
python domainFinder.py -u https://example.com --recursive --large-wordlist -t 100

# API-only scan
python domainFinder.py -u https://example.com --skip-brute --skip-search --skip-github

# Authenticated scan with cookies
python domainFinder.py -u https://example.com -c "sessionid=abc123; csrftoken=xyz789"
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Made with ❤️ by [Easin Arafat](https://profile.arafatops.com)**

⭐ Star this repository if you found it helpful!

</div>