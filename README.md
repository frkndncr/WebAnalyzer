# Web Analyzer Tool

## Overview
The **Web Analyzer Tool** is a comprehensive Python-based application designed for domain analysis, including WHOIS information retrieval, DNS records, subdomain discovery, SEO analysis, web technology detection, and advanced security analysis. The tool also features Cloudflare bypass capabilities, contact information discovery, zero-day vulnerability scanning, and subdomain takeover detection.

---

## Modules

The Web Analyzer features the following modules:

### Core Analysis Modules

- **Domain Info** - Retrieves comprehensive WHOIS information and registration details for domains.

- **Domain DNS** - Analyzes DNS records including A, AAAA, MX, NS, TXT and other record types.

- **Subfinder Tool** - Powerful subdomain discovery and enumeration capabilities.

- **SEO Analysis** - Evaluates search engine optimization factors including meta tags and content analysis.

- **Web Technologies** - Detects frontend and backend technologies, frameworks, and services.

### Security Modules

- **Security Analysis** - Performs comprehensive security checks for common vulnerabilities and misconfigurations.

- **Cloudflare Bypass** - Bypasses Cloudflare and other WAF protections to enable analysis of protected websites.

- **Nmap Zero Day** - Advanced vulnerability scanning to identify potential zero-day vulnerabilities.

- **Subdomain Takeover** - Detects vulnerable subdomains that are susceptible to takeover attacks.

### Advanced Modules

- **Advanced Content Scanner** - Deep analysis of web content to discover sensitive information and potential risks.

- **Contact Spy** - Discovers and extracts contact information from websites.

### Service Integration

- **Socket Service** - Run Web Analyzer as a service, enabling remote access and API-like functionality.

## Installation

### Requirements
Ensure the following dependencies are installed:
- Python 3.x
- Go (for Subfinder)
- Git

### Installation Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/frkndncr/WebAnalyzer.git
   cd WebAnalyzer
   ```
2. Run the Install Python Dependencies:
   ```bash
   pip install -r requirements.txt --break-system-packages
   ```
   
2. Run the setup script:
   ```bash
   ./setup.sh
   ```
   This script will:
   - Install required system packages.
   - Install and configure **Subfinder**.

3. Verify the installation:
   - Ensure `subfinder` is available in your PATH.
   - Ensure all Python modules are installed successfully.

---

## Usage

1. Run the main script:
   ```bash
   python main.py
   ```

2. Enter the domain name when prompted:
   ```
   Please enter a domain name (e.g., example.com): yourdomain.com
   ```

3. The tool will:
   - Perform all analyses.
   - Display results on the terminal.
   - Save all results in a structured JSON file under `logs/{domain}/results.json`.

---

## Project Structure

```plaintext
.
├── main.py                 # Entry point of the application
├── setup.sh                # Installation script
├── requirements.txt        # Python dependencies
├── logs/                   # Directory to store analysis results
├── modules/                # Directory containing all analysis modules
│   ├── domain_dns.py       # DNS record analysis module
│   ├── domain_info.py      # WHOIS information retrieval module
│   ├── seo_analysis.py     # SEO and analytics analysis module
│   ├── security_analysis.py# Security analysis module
│   ├── subfinder_tool.py   # Subdomain discovery module
│   ├── web_technologies.py # Web technology detection module
│   ├── subdomain_takeover.py # Subdomain takeover vulnerability detection module
│   ├── advanced_content_scanner.py # Advanced web content scanning module
└── tests/                  # Test scripts for the project
    └── test_main.py        # Unit tests for main.py
```

---

## Example Output Screenshot

![resim](https://github.com/user-attachments/assets/61580f3c-741b-46b3-aefb-5590f895f856)

### JSON Output:
The results are saved as `results.json` in the corresponding domain folder:

```json
{
  "Domain Information": {
    "Domain": "example.com",
    "Registrar Company": "Registrar Name",
    "Creation Date": "2020-01-01",
    "End Date": "2025-01-01",
    "Privacy Protection": "Effective",
    "Server Provider": "Cloudflare",
    "Physical Location": "San Francisco, US"
  },
  "DNS Records": {
    "A Records (IPv4)": ["192.168.0.1"],
    "MX Records (Mail Servers)": ["mail.example.com"],
    "Response Time (ms)": 35.5
  },
  "Subdomains": ["www.example.com", "blog.example.com"],
  "SEO Analysis": {
    "Meta Tags": {"Description": "Example description"},
    "Analytics Tools": {"Google Analytics IDs": ["UA-123456-7"]}
  },
  "Web Technologies": {
    "Backend Technologies": ["PHP", "WordPress"],
    "Frontend Technologies": ["Bootstrap"],
    "Content Delivery Network (CDN)": "Cloudflare"
  },
  "Security Analysis": {
    "Web Application Firewall": "Cloudflare",
    "SSL Info": {"Issuer": "Let's Encrypt"}
  },
  "Subdomain Takeover": {
    "Vulnerable Subdomains": [
      {
        "subdomain": "dev.example.com",
        "vulnerability_type": "Heroku Subdomain Takeover",
        "confidence": "High",
        "service": "Heroku",
        "exploitation_difficulty": "Medium",
        "mitigation": "Claim the subdomain or remove the DNS record"
      }
    ],
    "Statistics": {
      "total_subdomains_checked": 10,
      "high_confidence_vulnerabilities": 1,
      "medium_confidence_vulnerabilities": 0,
      "low_confidence_vulnerabilities": 0
    }
  },
  "Advanced Content Scan": {
    "summary": {
      "total_urls_crawled": 50,
      "total_js_files": 20,
      "total_api_endpoints": 15
    },
    "secrets": [
      {
        "type": "API Key",
        "source_url": "https://example.com/js/config.js",
        "severity": "High"
      }
    ],
    "js_vulnerabilities": [
      {
        "type": "Cross-Site Scripting (XSS)",
        "source_url": "https://example.com/main.js",
        "severity": "Medium"
      }
    ],
    "ssrf_vulnerabilities": [
      {
        "type": "Potential SSRF Endpoint",
        "source_url": "https://example.com/proxy",
        "severity": "High"
      }
    ]
  }
}
```

---

## Contribution

Feel free to contribute to this project by:
- Reporting issues.
- Suggesting features.
- Submitting pull requests.

---

## License

This project is licensed under the MIT License.

## Contact

- İnstagram: https://www.instagram.com/f3rrkan/
- LinkedIn: https://www.linkedin.com/in/furkan-dincer/
- Mail: hi@c4softwarestudio.com

---

