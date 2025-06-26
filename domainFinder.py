#!/usr/bin/env python3

#######################################
#    Author: Easin Arafat             #
#    GitHub: mrx-arafatt              #
#    Tool: Domain Finder v3.0         #
#    Enhanced Subdomain Discovery     #
#######################################

import os
import sys
import json
import time
import ssl
import socket
import re
import argparse
import threading
import hashlib
import pickle
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin
import requests
import dns.resolver
import dns.zone
import dns.query
import dns.rdatatype
from dotenv import load_dotenv
import termcolor
from bs4 import BeautifulSoup
import tldextract
import base64
from collections import Counter
from math import log2
import requests_cache
import urllib3

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load environment variables
load_dotenv()

class DomainFinder:
    def __init__(self):
        self.subdomains = set()
        self.secrets = {}
        self.cloud_urls = set()
        self.github_secrets = set()
        self.session = requests.Session()
        self.setup_session()
        self.load_config()
        self.setup_cache()

    def setup_session(self):
        """Setup requests session with headers and timeouts"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        ]

        self.session.headers.update({
            'User-Agent': user_agents[0],
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })

        # Setup proxy if configured
        if os.getenv('HTTP_PROXY'):
            self.session.proxies.update({
                'http': os.getenv('HTTP_PROXY'),
                'https': os.getenv('HTTPS_PROXY', os.getenv('HTTP_PROXY'))
            })

    def setup_cache(self):
        """Setup request caching"""
        if os.getenv('ENABLE_CACHE', 'true').lower() == 'true':
            cache_duration = int(os.getenv('CACHE_DURATION', '3600'))
            requests_cache.install_cache('domain_finder_cache', expire_after=cache_duration)

    def load_config(self):
        """Load configuration from environment"""
        self.config = {
            'max_threads': int(os.getenv('MAX_THREADS', '50')),
            'dns_timeout': int(os.getenv('DNS_TIMEOUT', '5')),
            'http_timeout': int(os.getenv('HTTP_TIMEOUT', '10')),
            'api_rate_limit': int(os.getenv('API_RATE_LIMIT', '10')),
            'dns_rate_limit': int(os.getenv('DNS_RATE_LIMIT', '100')),
            'use_large_wordlist': os.getenv('USE_LARGE_WORDLIST', 'true').lower() == 'true',
            'recursive_depth': int(os.getenv('RECURSIVE_DEPTH', '3')),
            'recursive_enabled': os.getenv('RECURSIVE_ENABLED', 'true').lower() == 'true',
            'verify_subdomains': os.getenv('VERIFY_SUBDOMAINS', 'true').lower() == 'true',
            'filter_wildcards': os.getenv('FILTER_WILDCARDS', 'true').lower() == 'true',
            'verbose': os.getenv('VERBOSE_OUTPUT', 'true').lower() == 'true'
        }

        # API Keys
        self.api_keys = {
            'securitytrails': os.getenv('SECURITYTRAILS_API_KEY'),
            'virustotal': os.getenv('VIRUSTOTAL_API_KEY'),
            'shodan': os.getenv('SHODAN_API_KEY'),
            'censys_id': os.getenv('CENSYS_API_ID'),
            'censys_secret': os.getenv('CENSYS_API_SECRET'),
            'github': os.getenv('GITHUB_TOKEN'),
            'urlvoid': os.getenv('URLVOID_API_KEY'),
            'spyse': os.getenv('SPYSE_API_KEY'),
            'riskiq_username': os.getenv('RISKIQ_USERNAME'),
            'riskiq_api_key': os.getenv('RISKIQ_API_KEY'),
            'otx': os.getenv('OTX_API_KEY')
        }

    def print_banner(self):
        """Print the tool banner"""
        banner = """

________                            .__          ___________.__             .___              
\______ \    ____    _____  _____   |__|  ____   \_   _____/|__|  ____    __| _/ ____ _______ 
 |    |  \  /  _ \  /     \ \__  \  |  | /    \   |    __)  |  | /    \  / __ |_/ __ \\_  __ \
 |    `   \(  <_> )|  Y Y  \ / __ \_|  ||   |  \  |     \   |  ||   |  \/ /_/ |\  ___/ |  | \/
/_______  / \____/ |__|_|  /(____  /|__||___|  /  \___  /   |__||___|  /\____ | \___  >|__|   
        \/               \/      \/          \/       \/             \/      \/     \/        
                             Enhanced Version 3.0
                                    By Easin Arafat
        Advanced Subdomain Discovery with Multiple Techniques
        """
        print(termcolor.colored(banner, 'cyan', attrs=['bold']))

    def log(self, message, level='info'):
        """Logging function"""
        if not self.config['verbose'] and level == 'debug':
            return

        colors = {
            'info': 'blue',
            'success': 'green',
            'warning': 'yellow',
            'error': 'red',
            'debug': 'white'
        }

        timestamp = datetime.now().strftime('%H:%M:%S')
        color = colors.get(level, 'white')

        if level == 'success':
            prefix = '[+]'
        elif level == 'error':
            prefix = '[-]'
        elif level == 'warning':
            prefix = '[!]'
        else:
            prefix = '[*]'

        print(termcolor.colored(f"{timestamp} {prefix} {message}", color))

    def load_wordlist(self):
        """Load subdomain wordlist"""
        wordlist_file = 'wordlists/large.txt' if self.config['use_large_wordlist'] else 'wordlists/common.txt'

        # Check for custom wordlist
        custom_wordlist = os.getenv('CUSTOM_WORDLIST_PATH')
        if custom_wordlist and os.path.exists(custom_wordlist):
            wordlist_file = custom_wordlist

        try:
            with open(wordlist_file, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip()]
            self.log(f"Loaded {len(wordlist)} words from {wordlist_file}", 'success')
            return wordlist
        except FileNotFoundError:
            self.log(f"Wordlist file {wordlist_file} not found, using default", 'warning')
            return ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging', 'blog', 'shop']

    def entropy(self, s):
        """Calculate Shannon entropy of a string"""
        if not s:
            return 0
        return -sum(i / len(s) * log2(i / len(s)) for i in Counter(s).values())

    def get_domain(self, url):
        """Extract domain from URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return urlparse(url).netloc.lower()

    def is_valid_subdomain(self, subdomain, domain):
        """Validate if subdomain is valid"""
        if not subdomain or not domain:
            return False

        # Remove protocol if present
        subdomain = subdomain.replace('http://', '').replace('https://', '')

        # Check if it's actually a subdomain of the target domain
        if not (subdomain.endswith('.' + domain) or subdomain == domain):
            return False

        # Filter out wildcards if configured
        if self.config['filter_wildcards'] and subdomain.startswith('*.'):
            return False

        # Basic validation
        if len(subdomain) > 253:  # Max domain length
            return False

        return True

    def verify_subdomain(self, subdomain):
        """Verify if subdomain resolves"""
        if not self.config['verify_subdomains']:
            return True

        try:
            dns.resolver.resolve(subdomain, 'A', lifetime=self.config['dns_timeout'])
            return True
        except:
            return False

    def certificate_transparency(self, domain):
        """Search Certificate Transparency logs"""
        self.log("Searching Certificate Transparency logs...", 'info')

        sources = [
            f"https://crt.sh/?q=%.{domain}&output=json",
            f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        ]

        found_count = 0

        for source in sources:
            try:
                response = self.session.get(source, timeout=self.config['http_timeout'])
                if response.status_code == 200:
                    if 'crt.sh' in source:
                        certificates = response.json()
                        for cert in certificates:
                            name_value = cert.get('name_value', '')
                            if name_value:
                                domains = name_value.split('\n')
                                for sub_domain in domains:
                                    sub_domain = sub_domain.strip().lower()
                                    if sub_domain.startswith('*.'):
                                        sub_domain = sub_domain[2:]

                                    if self.is_valid_subdomain(sub_domain, domain):
                                        if self.verify_subdomain(sub_domain):
                                            self.subdomains.add(sub_domain)
                                            found_count += 1

                    elif 'certspotter' in source:
                        data = response.json()
                        for item in data:
                            dns_names = item.get('dns_names', [])
                            for dns_name in dns_names:
                                dns_name = dns_name.lower()
                                if dns_name.startswith('*.'):
                                    dns_name = dns_name[2:]

                                if self.is_valid_subdomain(dns_name, domain):
                                    if self.verify_subdomain(dns_name):
                                        self.subdomains.add(dns_name)
                                        found_count += 1

            except Exception as e:
                self.log(f"CT logs search failed for {source}: {e}", 'error')

        self.log(f"Found {found_count} subdomains from CT logs", 'success')

    def dns_bruteforce(self, domain):
        """DNS brute force with wordlist"""
        self.log("Starting DNS brute force...", 'info')

        wordlist = self.load_wordlist()
        found_count = 0

        def check_subdomain(word):
            subdomain = f"{word}.{domain}"
            try:
                dns.resolver.resolve(subdomain, 'A', lifetime=self.config['dns_timeout'])
                self.subdomains.add(subdomain)
                self.log(f"Found: {subdomain}", 'success')
                return 1
            except:
                return 0

        with ThreadPoolExecutor(max_workers=self.config['max_threads']) as executor:
            futures = [executor.submit(check_subdomain, word) for word in wordlist]
            for future in as_completed(futures):
                found_count += future.result()

        self.log(f"DNS brute force completed. Found {found_count} subdomains", 'success')

    def ssl_certificate_check(self, domain):
        """Check SSL certificate for Subject Alternative Names"""
        self.log("Checking SSL certificate...", 'info')

        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=self.config['http_timeout']) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

                    found_count = 0
                    if 'subjectAltName' in cert:
                        for san_type, san_value in cert['subjectAltName']:
                            if san_type == 'DNS':
                                san_value = san_value.lower()
                                if san_value.startswith('*.'):
                                    san_value = san_value[2:]

                                if self.is_valid_subdomain(san_value, domain):
                                    if self.verify_subdomain(san_value):
                                        self.subdomains.add(san_value)
                                        found_count += 1

                    self.log(f"Found {found_count} subdomains from SSL certificate", 'success')

        except Exception as e:
            self.log(f"SSL certificate check failed: {e}", 'error')

    def zone_transfer(self, domain):
        """Attempt DNS zone transfer"""
        self.log("Attempting DNS zone transfer...", 'info')

        try:
            ns_records = dns.resolver.resolve(domain, 'NS', lifetime=self.config['dns_timeout'])
            nameservers = [str(ns) for ns in ns_records]

            found_count = 0
            for ns in nameservers:
                try:
                    self.log(f"Trying zone transfer from {ns}", 'debug')
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=self.config['dns_timeout']))

                    for name, node in zone.nodes.items():
                        subdomain = f"{name}.{domain}" if name != '@' else domain
                        if self.is_valid_subdomain(subdomain, domain):
                            self.subdomains.add(subdomain)
                            found_count += 1

                    self.log(f"Zone transfer successful from {ns}", 'success')

                except Exception as e:
                    self.log(f"Zone transfer failed from {ns}: {e}", 'debug')

            if found_count > 0:
                self.log(f"Found {found_count} subdomains from zone transfer", 'success')
            else:
                self.log("No zone transfers allowed", 'info')

        except Exception as e:
            self.log(f"Zone transfer enumeration failed: {e}", 'error')

    def search_engines(self, domain):
        """Search engines for subdomains"""
        self.log("Searching via search engines...", 'info')

        queries = [
            f"site:*.{domain}",
            f"site:{domain} -www",
            f"inurl:{domain}",
            f"intitle:{domain}",
            f"filetype:pdf site:{domain}",
            f"filetype:doc site:{domain}",
            f"filetype:xls site:{domain}"
        ]

        found_count = 0

        for query in queries:
            try:
                # Google dorking (limited due to rate limiting)
                url = f"https://www.google.com/search?q={query}&num=100"
                response = self.session.get(url, timeout=self.config['http_timeout'])

                # Extract domains from search results
                domain_pattern = r'https?://([a-zA-Z0-9.-]+\.' + re.escape(domain) + r')'
                matches = re.findall(domain_pattern, response.text, re.IGNORECASE)

                for match in matches:
                    match = match.lower()
                    if self.is_valid_subdomain(match, domain):
                        if self.verify_subdomain(match):
                            self.subdomains.add(match)
                            found_count += 1

                time.sleep(1)  # Reduced delay

            except Exception as e:
                self.log(f"Search engine query failed: {e}", 'debug')

        self.log(f"Found {found_count} subdomains from search engines", 'success')

    def third_party_apis(self, domain):
        """Query third-party APIs for subdomains"""
        self.log("Querying third-party APIs...", 'info')

        found_count = 0

        # HackerTarget API (free, no key required)
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            response = self.session.get(url, timeout=self.config['http_timeout'])
            if response.status_code == 200:
                lines = response.text.strip().split('\n')
                for line in lines:
                    if ',' in line:
                        subdomain = line.split(',')[0].strip().lower()
                        if self.is_valid_subdomain(subdomain, domain):
                            if self.verify_subdomain(subdomain):
                                self.subdomains.add(subdomain)
                                found_count += 1
        except Exception as e:
            self.log(f"HackerTarget API failed: {e}", 'debug')

        # SecurityTrails API
        if self.api_keys['securitytrails']:
            try:
                headers = {'APIKEY': self.api_keys['securitytrails']}
                url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
                response = self.session.get(url, headers=headers, timeout=self.config['http_timeout'])

                if response.status_code == 200:
                    data = response.json()
                    subdomains = data.get('subdomains', [])
                    for sub in subdomains:
                        subdomain = f"{sub}.{domain}"
                        if self.verify_subdomain(subdomain):
                            self.subdomains.add(subdomain)
                            found_count += 1

            except Exception as e:
                self.log(f"SecurityTrails API failed: {e}", 'debug')

        # VirusTotal API
        if self.api_keys['virustotal']:
            try:
                headers = {'x-apikey': self.api_keys['virustotal']}
                url = f"https://www.virustotal.com/vtapi/v2/domain/report"
                params = {'apikey': self.api_keys['virustotal'], 'domain': domain}
                response = self.session.get(url, headers=headers, params=params, timeout=self.config['http_timeout'])

                if response.status_code == 200:
                    data = response.json()
                    subdomains = data.get('subdomains', [])
                    for subdomain in subdomains:
                        subdomain = subdomain.lower()
                        if self.is_valid_subdomain(subdomain, domain):
                            if self.verify_subdomain(subdomain):
                                self.subdomains.add(subdomain)
                                found_count += 1

            except Exception as e:
                self.log(f"VirusTotal API failed: {e}", 'debug')

        self.log(f"Found {found_count} subdomains from third-party APIs", 'success')

    def github_scanning(self, domain):
        """Scan GitHub repositories for subdomains"""
        if not self.api_keys['github']:
            self.log("GitHub token not provided, skipping GitHub scanning", 'warning')
            return

        self.log("Scanning GitHub repositories...", 'info')

        headers = {
            'Authorization': f"token {self.api_keys['github']}",
            'Accept': 'application/vnd.github.v3+json'
        }

        found_count = 0

        # Search for repositories mentioning the domain
        search_queries = [
            f'"{domain}"',
            f'"{domain}" subdomain',
            f'"{domain}" dns',
            f'"{domain}" certificate'
        ]

        for query in search_queries:
            try:
                url = f"https://api.github.com/search/repositories?q={query}&sort=updated&order=desc&per_page=3"
                response = self.session.get(url, headers=headers, timeout=5)

                if response.status_code == 200:
                    data = response.json()
                    repositories = data.get('items', [])

                    for repo in repositories[:10]:  # Limit to top 10 repos
                        repo_name = repo['full_name']
                        self.log(f"Scanning repository: {repo_name}", 'debug')

                        # Get repository contents
                        contents_url = f"https://api.github.com/repos/{repo_name}/contents"
                        contents_response = self.session.get(contents_url, headers=headers, timeout=self.config['http_timeout'])

                        if contents_response.status_code == 200:
                            contents = contents_response.json()

                            for item in contents:
                                if item['type'] == 'file' and item['name'].endswith(('.txt', '.md', '.json', '.yml', '.yaml', '.conf')):
                                    # Download and scan file content
                                    file_url = item['download_url']
                                    file_response = self.session.get(file_url, timeout=self.config['http_timeout'])

                                    if file_response.status_code == 200:
                                        content = file_response.text

                                        # Extract subdomains from content
                                        domain_pattern = r'([a-zA-Z0-9.-]+\.' + re.escape(domain) + r')'
                                        matches = re.findall(domain_pattern, content, re.IGNORECASE)

                                        for match in matches:
                                            match = match.lower()
                                            if self.is_valid_subdomain(match, domain):
                                                if self.verify_subdomain(match):
                                                    self.subdomains.add(match)
                                                    found_count += 1

                time.sleep(1)  # Rate limiting

            except Exception as e:
                self.log(f"GitHub scanning failed: {e}", 'debug')

        self.log(f"Found {found_count} subdomains from GitHub", 'success')

    def passive_dns(self, domain):
        """Query passive DNS databases"""
        self.log("Querying passive DNS databases...", 'info')

        found_count = 0

        # RiskIQ PassiveTotal
        if self.api_keys['riskiq_username'] and self.api_keys['riskiq_api_key']:
            try:
                auth = (self.api_keys['riskiq_username'], self.api_keys['riskiq_api_key'])
                url = f"https://api.passivetotal.org/v2/enrichment/subdomains"
                params = {'query': domain}
                response = self.session.get(url, auth=auth, params=params, timeout=self.config['http_timeout'])

                if response.status_code == 200:
                    data = response.json()
                    subdomains = data.get('subdomains', [])
                    for sub in subdomains:
                        subdomain = f"{sub}.{domain}"
                        if self.verify_subdomain(subdomain):
                            self.subdomains.add(subdomain)
                            found_count += 1

            except Exception as e:
                self.log(f"RiskIQ PassiveTotal failed: {e}", 'debug')

        # AlienVault OTX
        if self.api_keys['otx']:
            try:
                headers = {'X-OTX-API-KEY': self.api_keys['otx']}
                url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
                response = self.session.get(url, headers=headers, timeout=self.config['http_timeout'])

                if response.status_code == 200:
                    data = response.json()
                    passive_dns = data.get('passive_dns', [])
                    for record in passive_dns:
                        hostname = record.get('hostname', '').lower()
                        if self.is_valid_subdomain(hostname, domain):
                            if self.verify_subdomain(hostname):
                                self.subdomains.add(hostname)
                                found_count += 1

            except Exception as e:
                self.log(f"AlienVault OTX failed: {e}", 'debug')

        self.log(f"Found {found_count} subdomains from passive DNS", 'success')

    def recursive_discovery(self, domain, depth=0):
        """Recursive subdomain discovery"""
        if not self.config['recursive_enabled'] or depth >= self.config['recursive_depth']:
            return

        self.log(f"Starting recursive discovery (depth {depth + 1})...", 'info')

        current_subdomains = list(self.subdomains)
        new_subdomains = set()

        for subdomain in current_subdomains:
            if subdomain != domain:  # Don't recurse on the main domain
                # Try common patterns
                patterns = ['www', 'api', 'admin', 'dev', 'test', 'staging', 'mail', 'ftp']

                for pattern in patterns:
                    new_subdomain = f"{pattern}.{subdomain}"

                    try:
                        dns.resolver.resolve(new_subdomain, 'A', lifetime=self.config['dns_timeout'])
                        if new_subdomain not in self.subdomains:
                            new_subdomains.add(new_subdomain)
                            self.subdomains.add(new_subdomain)
                            self.log(f"Recursive found: {new_subdomain}", 'success')
                    except:
                        pass

        if new_subdomains and depth < self.config['recursive_depth'] - 1:
            self.recursive_discovery(domain, depth + 1)

        self.log(f"Recursive discovery completed at depth {depth + 1}", 'success')

    def javascript_analysis(self, url):
        """Analyze JavaScript files for subdomains and secrets"""
        self.log("Analyzing JavaScript files...", 'info')

        domain = self.get_domain(url)

        try:
            response = self.session.get(url, timeout=self.config['http_timeout'], verify=False)
            if response.status_code != 200:
                return

            soup = BeautifulSoup(response.text, 'html.parser')

            # Find inline JavaScript
            inline_scripts = soup.find_all('script', string=True)
            external_scripts = soup.find_all('script', src=True)

            all_js_content = []

            # Process inline scripts
            for script in inline_scripts:
                if script.string:
                    all_js_content.append(script.string)

            # Process external scripts
            for script in external_scripts:
                src = script.get('src')
                if src:
                    if src.startswith('//'):
                        src = 'https:' + src
                    elif src.startswith('/'):
                        src = urljoin(url, src)
                    elif not src.startswith(('http://', 'https://')):
                        src = urljoin(url, src)

                    try:
                        js_response = self.session.get(src, timeout=self.config['http_timeout'], verify=False)
                        if js_response.status_code == 200:
                            all_js_content.append(js_response.text)
                    except:
                        pass

            # Analyze all JavaScript content
            found_subdomains = 0
            found_secrets = 0

            for js_content in all_js_content:
                # Find subdomains
                domain_pattern = r'([a-zA-Z0-9.-]+\.' + re.escape(domain) + r')'
                subdomain_matches = re.findall(domain_pattern, js_content, re.IGNORECASE)

                for match in subdomain_matches:
                    match = match.lower()
                    if self.is_valid_subdomain(match, domain):
                        if self.verify_subdomain(match):
                            self.subdomains.add(match)
                            found_subdomains += 1

                # Find secrets (high entropy strings)
                secret_patterns = [
                    r'(["\']?[a-zA-Z0-9_-]*(?:api[_-]?key|secret|token|password|auth)[a-zA-Z0-9_-]*["\']?\s*[:=]\s*["\']?([a-zA-Z0-9+/=_-]{20,})["\']?)',
                    r'(["\']?(?:aws[_-]?access[_-]?key[_-]?id|aws[_-]?secret[_-]?access[_-]?key)["\']?\s*[:=]\s*["\']?([A-Z0-9]{20,})["\']?)',
                    r'(["\']?github[_-]?token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_]{40,})["\']?)',
                    r'(["\']?bearer["\']?\s*[:=]\s*["\']?([a-zA-Z0-9+/=_-]{20,})["\']?)'
                ]

                for pattern in secret_patterns:
                    matches = re.findall(pattern, js_content, re.IGNORECASE)
                    for match in matches:
                        if len(match) >= 2:
                            secret_value = match[1]
                            if self.entropy(secret_value) > 3:  # High entropy threshold
                                if url not in self.secrets:
                                    self.secrets[url] = []
                                self.secrets[url].append(secret_value)
                                found_secrets += 1

            self.log(f"JavaScript analysis found {found_subdomains} subdomains and {found_secrets} secrets", 'success')

        except Exception as e:
            self.log(f"JavaScript analysis failed: {e}", 'error')

    def run_all_techniques(self, url, cookie=None):
        """Run all subdomain discovery techniques"""
        self.print_banner()

        domain = self.get_domain(url)
        self.log(f"Starting comprehensive subdomain enumeration for: {domain}", 'info')
        self.log(f"Using {self.config['max_threads']} threads", 'info')
        print("-" * 80)

        start_time = time.time()

        # Add cookie to session if provided
        if cookie:
            self.session.headers.update({'Cookie': cookie})
            self.log("Using provided cookies", 'info')

        # Run all discovery techniques
        techniques = [
            ('Certificate Transparency', lambda: self.certificate_transparency(domain)),
            ('SSL Certificate Check', lambda: self.ssl_certificate_check(domain)),
            ('DNS Brute Force', lambda: self.dns_bruteforce(domain)),
            ('Zone Transfer', lambda: self.zone_transfer(domain)),
            ('Search Engines', lambda: self.search_engines(domain)),
            ('Third-party APIs', lambda: self.third_party_apis(domain)),
            ('GitHub Scanning', lambda: self.github_scanning(domain)),
            ('Passive DNS', lambda: self.passive_dns(domain)),
            ('JavaScript Analysis', lambda: self.javascript_analysis(url)),
        ]

        # Execute techniques with threading
        with ThreadPoolExecutor(max_workers=min(len(techniques), 5)) as executor:
            futures = []
            for name, technique in techniques:
                future = executor.submit(technique)
                futures.append((name, future))

            for name, future in futures:
                try:
                    future.result(timeout=120)  # 2 minute timeout per technique
                except Exception as e:
                    self.log(f"{name} failed: {e}", 'error')

        # Recursive discovery
        if self.config['recursive_enabled']:
            self.recursive_discovery(domain)

        end_time = time.time()

        # Results summary
        print("-" * 80)
        self.log(f"Enumeration completed in {end_time - start_time:.2f} seconds", 'success')
        self.log(f"Total unique subdomains found: {len(self.subdomains)}", 'success')

        if self.secrets:
            total_secrets = sum(len(secrets) for secrets in self.secrets.values())
            self.log(f"Total secrets found: {total_secrets}", 'success')

        print("-" * 80)

        return self.get_results()

    def get_results(self):
        """Get organized results"""
        return {
            'subdomains': sorted(list(self.subdomains)),
            'secrets': self.secrets,
            'cloud_urls': sorted(list(self.cloud_urls)),
            'github_secrets': sorted(list(self.github_secrets))
        }

    def save_results(self, results, output_dir='results'):
        """Save results to files"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # Save subdomains
        subdomain_file = os.path.join(output_dir, f'subdomains_{timestamp}.txt')
        with open(subdomain_file, 'w') as f:
            for subdomain in results['subdomains']:
                f.write(f"{subdomain}\n")

        # Save secrets
        if results['secrets']:
            secrets_file = os.path.join(output_dir, f'secrets_{timestamp}.json')
            with open(secrets_file, 'w') as f:
                json.dump(results['secrets'], f, indent=2)

        # Save cloud URLs
        if results['cloud_urls']:
            cloud_file = os.path.join(output_dir, f'cloud_urls_{timestamp}.txt')
            with open(cloud_file, 'w') as f:
                for url in results['cloud_urls']:
                    f.write(f"{url}\n")

        self.log(f"Results saved to {output_dir}/", 'success')
        return subdomain_file

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Domain Finder v3.0 - Advanced Subdomain Discovery',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python domainFinder_enhanced.py -u https://example.com
  python domainFinder_enhanced.py -u https://example.com -c "session=abc123; token=xyz789"
  python domainFinder_enhanced.py -u https://example.com -o results/ -t 100
  python domainFinder_enhanced.py -u https://example.com --recursive --depth 3
  python domainFinder_enhanced.py -u https://example.com --no-verify --large-wordlist

Features:
  ✓ Certificate Transparency logs
  ✓ DNS brute forcing with large wordlists
  ✓ SSL certificate SAN checking
  ✓ DNS zone transfer attempts
  ✓ Search engine dorking
  ✓ Third-party API integration
  ✓ GitHub repository scanning
  ✓ Passive DNS databases
  ✓ JavaScript analysis for secrets
  ✓ Recursive subdomain discovery
  ✓ Multi-threaded execution
  ✓ Request caching
  ✓ Wildcard filtering
        """
    )

    # Required arguments
    parser.add_argument('-u', '--url', required=True,
                       help='Target URL or domain (e.g., https://example.com or example.com)')

    # Optional arguments
    parser.add_argument('-c', '--cookie',
                       help='Cookies to send with requests (format: "name=value; name2=value2")')
    parser.add_argument('-o', '--output', default='results',
                       help='Output directory for results (default: results)')
    parser.add_argument('-t', '--threads', type=int, default=50,
                       help='Number of threads for DNS brute force (default: 50)')
    parser.add_argument('--timeout', type=int, default=10,
                       help='HTTP timeout in seconds (default: 10)')
    parser.add_argument('--dns-timeout', type=int, default=5,
                       help='DNS timeout in seconds (default: 5)')

    # Discovery options
    parser.add_argument('--recursive', action='store_true',
                       help='Enable recursive subdomain discovery')
    parser.add_argument('--depth', type=int, default=3,
                       help='Recursive discovery depth (default: 3)')
    parser.add_argument('--large-wordlist', action='store_true',
                       help='Use large wordlist for brute forcing')
    parser.add_argument('--custom-wordlist',
                       help='Path to custom wordlist file')

    # Verification options
    parser.add_argument('--no-verify', action='store_true',
                       help='Skip DNS verification of found subdomains')
    parser.add_argument('--no-wildcards', action='store_true',
                       help='Filter out wildcard subdomains')

    # Output options
    parser.add_argument('--json', action='store_true',
                       help='Output results in JSON format')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--quiet', action='store_true',
                       help='Suppress banner and progress messages')

    # Technique selection
    parser.add_argument('--skip-ct', action='store_true',
                       help='Skip Certificate Transparency logs')
    parser.add_argument('--skip-dns', action='store_true',
                       help='Skip DNS brute forcing')
    parser.add_argument('--skip-search', action='store_true',
                       help='Skip search engine dorking')
    parser.add_argument('--skip-apis', action='store_true',
                       help='Skip third-party APIs')
    parser.add_argument('--skip-github', action='store_true',
                       help='Skip GitHub scanning')
    parser.add_argument('--skip-js', action='store_true',
                       help='Skip JavaScript analysis')

    args = parser.parse_args()

    # Override environment variables with command line arguments
    if args.threads:
        os.environ['MAX_THREADS'] = str(args.threads)
    if args.timeout:
        os.environ['HTTP_TIMEOUT'] = str(args.timeout)
    if args.dns_timeout:
        os.environ['DNS_TIMEOUT'] = str(args.dns_timeout)
    if args.recursive:
        os.environ['RECURSIVE_ENABLED'] = 'true'
    if args.depth:
        os.environ['RECURSIVE_DEPTH'] = str(args.depth)
    if args.large_wordlist:
        os.environ['USE_LARGE_WORDLIST'] = 'true'
    if args.custom_wordlist:
        os.environ['CUSTOM_WORDLIST_PATH'] = args.custom_wordlist
    if args.no_verify:
        os.environ['VERIFY_SUBDOMAINS'] = 'false'
    if args.no_wildcards:
        os.environ['FILTER_WILDCARDS'] = 'true'
    if args.verbose:
        os.environ['VERBOSE_OUTPUT'] = 'true'
    if args.quiet:
        os.environ['VERBOSE_OUTPUT'] = 'false'

    # Initialize Domain Finder
    finder = DomainFinder()

    # Run enumeration
    try:
        results = finder.run_all_techniques(args.url, args.cookie)

        # Display results
        if not args.quiet:
            print("\n" + "="*80)
            print("RESULTS SUMMARY")
            print("="*80)

        if args.json:
            print(json.dumps(results, indent=2))
        else:
            print(f"\nSubdomains found ({len(results['subdomains'])}):")
            print("-" * 40)
            for subdomain in results['subdomains']:
                print(subdomain)

            print(f"\n🔗 Clickable Links:")
            print("-" * 40)
            for subdomain in results['subdomains']:
                print(f"https://{subdomain}")

            if results['secrets']:
                print(f"\nSecrets found ({sum(len(secrets) for secrets in results['secrets'].values())}):")
                print("-" * 40)
                for source, secrets in results['secrets'].items():
                    print(f"\nFrom {source}:")
                    for secret in secrets:
                        print(f"  {secret}")

            if results['cloud_urls']:
                print(f"\nCloud URLs found ({len(results['cloud_urls'])}):")
                print("-" * 40)
                for url in results['cloud_urls']:
                    print(url)

        # Save results
        output_file = finder.save_results(results, args.output)

        if not args.quiet:
            print(f"\n[+] Results saved to: {output_file}")
            print(f"[+] Total subdomains: {len(results['subdomains'])}")
            if results['secrets']:
                print(f"[+] Total secrets: {sum(len(secrets) for secrets in results['secrets'].values())}")

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
