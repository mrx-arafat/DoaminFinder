# Domain Finder 🔍

**Simple & Powerful Subdomain Discovery Tool**

[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Author](https://img.shields.io/badge/Author-Easin%20Arafat-red.svg)](https://profile.arafatops.com)

> Fast subdomain discovery with HTTP status codes - Find subdomains and see which ones are live!

## ✨ What It Does

Domain Finder discovers subdomains and shows you their HTTP status codes so you know which ones are actually working:

```
🔗 Clickable Links with Status Codes:
https://www.example.com [200]  ← Working!
https://api.example.com [404]  ← Not found
https://admin.example.com [403] ← Forbidden (interesting!)
https://dev.example.com [503]  ← Service down
```

## 🚀 Quick Start

### 1. Install
```bash
git clone https://github.com/mrx-arafat/domain-finder.git
cd domain-finder
pip install -r requirements.txt
```

### 2. Run
```bash
python domainFinder.py -u example.com
```

That's it! 🎉

## 📖 Usage Examples

### Basic Scan
```bash
# Simple subdomain discovery
python domainFinder.py -u tesla.com
```

### With API Keys (Better Results)
```bash
# Create .env file with your API keys
echo "SECURITYTRAILS_API_KEY=your_key" > .env
echo "VIRUSTOTAL_API_KEY=your_key" >> .env

# Run scan
python domainFinder.py -u tesla.com
```

### Advanced Options
```bash
# Fast scan with more threads
python domainFinder.py -u tesla.com -t 100

# Recursive discovery (finds more subdomains)
python domainFinder.py -u tesla.com --recursive

# Use large wordlist for thorough scanning
python domainFinder.py -u tesla.com --large-wordlist

# Authenticated scan with cookies
python domainFinder.py -u tesla.com -c "session=abc123; token=xyz789"
```

## 🎯 Key Features

- **Multiple Discovery Methods** - Certificate logs, DNS brute force, APIs, GitHub scanning
- **HTTP Status Codes** - See which subdomains are live (200), forbidden (403), not found (404), etc.
- **Fast & Efficient** - Multi-threaded scanning with smart caching
- **API Integration** - Works with SecurityTrails, VirusTotal, Shodan for better results
- **Cookie Support** - Scan authenticated areas with your session cookies
- **Smart Output** - Results saved as `domain_time_date` format

## 📊 Sample Output

```
Domain Finder v3.0 - Starting scan for tesla.com...

🔗 Clickable Links with Status Codes:
----------------------------------------
https://www.tesla.com [200]
https://shop.tesla.com [200]
https://service.tesla.com [200]
https://supercharger.tesla.com [200]
https://auth.tesla.com [403]
https://owner-api.tesla.com [401]
https://internal.tesla.com [404]

[+] Results saved to: tesla_com_1234_0627/subdomains_20250627_123456.txt
[+] Total subdomains: 936
```

## ⚙️ Configuration

### Optional API Keys (.env file)
```bash
# For better results, add these to .env file:
SECURITYTRAILS_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
GITHUB_TOKEN=your_token_here
```

### Common Options
```bash
-u, --url          Target domain (required)
-t, --threads      Number of threads (default: 50)
-o, --output       Output directory
--recursive        Find subdomains of subdomains
--large-wordlist   Use bigger wordlist (slower but more thorough)
--quiet            Less output
--json             JSON output format
```

## 📁 Output Files

Results are saved in `domain_time_date/` folder:
- `subdomains_timestamp.txt` - Main results with status codes
- `secrets_timestamp.json` - Any secrets found (API keys, etc.)
- `cloud_urls_timestamp.txt` - Cloud service URLs

## 🛠️ Troubleshooting

**No subdomains found?**
- Add API keys to `.env` file for better results
- Try `--large-wordlist` for more thorough scanning
- Use `--recursive` to find subdomains of subdomains

**Slow scanning?**
- Increase threads: `-t 100`
- Skip techniques: `--skip-github --skip-js`

**Need authentication?**
- Use cookies: `-c "session=your_session_cookie"`

## 🤝 Contributing

Found a bug or want to add a feature? Pull requests welcome!

## 📄 License

MIT License - feel free to use and modify!

## 👨‍💻 Author

**Easin Arafat**
- Website: [profile.arafatops.com](https://profile.arafatops.com)
- GitHub: [@mrx-arafat](https://github.com/mrx-arafat)

---

⭐ **Star this repo if you find it useful!** ⭐