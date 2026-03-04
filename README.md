# SiteQ8 CyberToolkit 🔒

> A powerful, modular bash-based cybersecurity toolkit for ethical security assessment, recon, and analysis.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Shell](https://img.shields.io/badge/shell-bash-orange)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey)

---

```
  ██████╗ ██╗████████╗███████╗ ██████╗ █████╗ 
 ██╔════╝ ██║╚══██╔══╝██╔════╝██╔═══██╗╚════██╗
 ╚██████╗ ██║   ██║   █████╗  ██║   ██║ █████╔╝
  ╚════██╗██║   ██║   ██╔══╝  ██║▄▄ ██║ ╔══██╗
  ██████╔╝██║   ██║   ███████╗╚██████╔╝ █████╔╝
  ╚═════╝ ╚═╝   ╚═╝   ╚══════╝ ╚══▀▀═╝ ╚════╝ 
```

---

## ⚠️ Legal Disclaimer

> **This tool is for authorized security testing and educational purposes only.**  
> Unauthorized scanning, probing, or attacking systems is illegal in most jurisdictions.  
> The author is not responsible for misuse. Always get written permission before testing.

---

## ✨ Features

| Module | Description |
|---|---|
| 🌐 Network Recon | Ping, traceroute, ARP, interfaces, routing, connections |
| 🔍 Port Scanner | TCP scan with nmap (or bash fallback), service banners, risk reference |
| 🧬 DNS Enumerator | A/AAAA/MX/NS/TXT/SOA/CNAME, DMARC/SPF audit, zone transfer test |
| 🔐 SSL/TLS Analyzer | Cert validity, expiry, protocol support, weak ciphers, entropy |
| 🔎 HTTP Headers | Security headers audit, scoring, cookie flags, info disclosure |
| 🕵️ Subdomain Finder | 80+ wordlist + crt.sh CT logs + takeover detection |
| 📡 Whois & IP Intel | Domain whois, IP geolocation/ASN, Shodan/VT/Censys links |
| 🧪 Web Fingerprinter | CMS, frameworks, JS libraries, CDN, WAF, sensitive file check |
| 🔑 Password Auditor | Entropy analysis, crack-time estimate, policy check, batch audit |
| 📋 Log Analyzer | Web/auth log parsing, attack detection (SQLi, XSS, LFI, brute-force) |
| 🚀 Full Recon Suite | Runs all modules in sequence with a master report |

---

## 🚀 Quick Start

```bash
# Clone the repo
git clone https://github.com/SiteQ8/SiteQ8-CyberToolkit.git
cd SiteQ8-CyberToolkit

# Make executable
chmod +x toolkit.sh modules/*.sh

# Run interactive menu
./toolkit.sh

# Run specific module
./toolkit.sh --module 3

# Run module against a target directly
./toolkit.sh --module 5 --target example.com
```

---

## 📦 Dependencies

### Required (minimal)
| Tool | Purpose |
|---|---|
| `bash 4+` | Core shell |
| `curl` | HTTP requests, geo lookup |
| `dig` | DNS queries |

### Optional (enhance functionality)
| Tool | Purpose | Install |
|---|---|---|
| `nmap` | Advanced port scanning | `apt install nmap` |
| `whois` | Domain registration data | `apt install whois` |
| `openssl` | SSL/TLS analysis | `apt install openssl` |
| `traceroute` | Route tracing | `apt install traceroute` |

The toolkit gracefully falls back when optional tools are missing.

---

## 🗂 File Structure

```
SiteQ8-CyberToolkit/
├── toolkit.sh              # Main entry point
├── lib/
│   ├── colors.sh           # ANSI color definitions
│   └── utils.sh            # Shared utilities (logging, tables, scoring)
├── modules/
│   ├── net_recon.sh        # Network reconnaissance
│   ├── port_scanner.sh     # Port & service scanner
│   ├── dns_enum.sh         # DNS enumeration
│   ├── ssl_analyzer.sh     # SSL/TLS analysis
│   ├── http_headers.sh     # HTTP security header audit
│   ├── subdomain_finder.sh # Subdomain discovery
│   ├── whois_intel.sh      # Whois + IP intelligence
│   ├── web_fingerprint.sh  # Technology fingerprinting
│   ├── password_auditor.sh # Password strength analysis
│   ├── log_analyzer.sh     # Log-based attack detection
│   └── full_recon.sh       # Combined recon suite
└── reports/                # Auto-generated reports (gitignored)
```

---

## 📊 Report Output

Every module generates a timestamped report in `reports/`:

```
reports/
  ssl_tls_example_com_20240301_143022.txt
  dns_enum_example_com_20240301_143500.txt
  full_recon_example_com_20240301_144000.txt
```

Filter all findings from a full recon report:
```bash
grep '\[FINDING\]' reports/full_recon_*.txt
```

---

## 🧩 Module Details

### 🔍 Port Scanner
- Uses **nmap** (preferred) with service version detection
- Falls back to pure **bash /dev/tcp** scanner — no dependencies required
- Detects and warns on high-risk open ports (RDP, MongoDB, SMB, etc.)
- Modes: Common ports | Full 1–65535 | Custom range

### 🧬 DNS Enumerator
- Checks A, AAAA, MX, NS, TXT, CNAME, SOA records
- SPF `+all` detection (mail spoofing risk)
- DMARC presence and enforcement level
- **Zone transfer (AXFR)** attempt against all nameservers
- Reverse PTR lookup

### 🔐 SSL/TLS Analyzer
- Certificate details: subject, issuer, SANs, serial, key size
- Expiry countdown with severity-based alerts
- Protocol support: SSLv2/v3, TLS 1.0/1.1/1.2/1.3
- Weak cipher detection (RC4, DES, 3DES, MD5, EXPORT, NULL)
- SHA-1 signature detection

### 🔎 HTTP Headers Inspector
- Audits 9 security headers with scoring bar
- Cookie flag analysis: `HttpOnly`, `Secure`, `SameSite`
- Server banner and `X-Powered-By` disclosure detection
- WAF detection via response headers

### 🕵️ Subdomain Finder
- 80+ curated subdomain wordlist
- Real-time HTTP status verification for each found subdomain
- **Subdomain takeover** detection (GitHub Pages, Heroku, S3, Netlify, etc.)
- Certificate Transparency via `crt.sh` for passive discovery

### 🔑 Password Auditor
- Entropy calculation (bits) per password
- Crack-time estimates: online (1K/s), offline (1B/s), GPU cluster (1T/s)
- Pattern detection: keyboard walks, dictionary words, repetition
- Top-100 common password check
- Batch file audit mode

### 📋 Log Analyzer
- Detects: SQL injection, XSS, path traversal, RCE attempts, scanner/bot UA
- Brute-force detection (IP-based 401 flood analysis)
- Top requesting IPs with threat scoring
- Auth log: failed logins, sudo activity, session events
- Demo mode for testing without real logs

---

## 💡 Usage Examples

```bash
# Interactive menu
./toolkit.sh

# DNS enumeration on a domain
./toolkit.sh --module 3 --target example.com

# Check SSL certificate
./toolkit.sh --module 4 --target example.com

# Full recon (requires authorization confirmation)
./toolkit.sh --module 11 --target example.com

# Audit a password list
./toolkit.sh --module 9
# then choose [2] and provide path to file

# Analyze your web server logs for attacks
./toolkit.sh --module 10
# then choose [1] — auto-detects Apache/Nginx logs
```

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-module`
3. Commit your changes: `git commit -m 'Add new module: XYZ'`
4. Push and open a Pull Request

Ideas for new modules:
- `firewall_audit.sh` — iptables/nftables rule review
- `cms_scanner.sh` — WordPress/Joomla CVE checks  
- `email_spoof_test.sh` — SPF/DKIM/DMARC sender test
- `cloud_enum.sh` — S3/GCS bucket enumeration
- `vuln_scanner.sh` — CVE-based version matching

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

**Made with ❤️ by [SiteQ8](https://github.com/SiteQ8)**

*For educational and authorized security testing only.*

</div>
