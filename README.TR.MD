# WebAnalyzer - Advanced Domain Security & Intelligence Tool

<div align="center">

![WebAnalyzer Banner](https://img.shields.io/badge/WebAnalyzer-v2.0-blue?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.8+-green?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-red?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-Focused-orange?style=for-the-badge)

**Comprehensive domain analysis and security assessment toolkit for cybersecurity professionals**

</div>

## 🚀 Overview

WebAnalyzer is a powerful Python-based domain analysis framework designed for cybersecurity professionals, penetration testers, and security researchers. It combines reconnaissance, vulnerability assessment, and intelligence gathering into a single comprehensive toolkit with advanced IP rotation and rate limiting protection.

### ✨ Key Features

- **12 Advanced Analysis Modules** - From basic domain info to aggressive API security testing
- **IP Rotation & Rate Limiting Protection** - Built-in evasion capabilities
- **Comprehensive Security Testing** - Multiple vulnerability detection techniques
- **Intelligence Gathering** - OSINT and contact information discovery
- **Professional Reporting** - Detailed JSON reports with risk scoring
- **Modular Architecture** - Easy to extend and customize

---

## 🛠️ Analysis Modules

### 📊 Core Intelligence Modules

| Module | Description | Risk Level |
|--------|-------------|------------|
| **Domain Information** | WHOIS data, registration details, DNS records | Low |
| **DNS Analysis** | Comprehensive DNS record enumeration and analysis | Low |
| **SEO Analysis** | Search engine optimization assessment with 13 categories | Low |
| **Web Technologies** | Frontend/backend technology stack detection | Low |

### 🔍 Reconnaissance Modules

| Module | Description | Risk Level |
|--------|-------------|------------|
| **Subdomain Discovery** | Advanced subdomain enumeration using Subfinder | Medium |
| **Contact Intelligence** | Email, phone, and social media profile extraction | Medium |
| **Advanced Content Scanner** | Deep web content analysis for sensitive information | Medium |

### 🔒 Security Assessment Modules

| Module | Description | Risk Level |
|--------|-------------|------------|
| **Security Analysis** | Security headers, SSL/TLS configuration assessment | Medium |
| **Subdomain Takeover** | Automated subdomain takeover vulnerability detection | High |
| **CloudFlare Bypass** | WAF bypass techniques and real IP discovery | High |
| **Network Scanner** | Advanced port scanning and service enumeration | High |
| **API Security Scanner** | Aggressive API vulnerability assessment and exploitation | Critical |

---

## ⚡ Installation

### Prerequisites
```bash
# Required dependencies
- Python 3.8+
- Go (for Subfinder integration)
- Git
```

### Quick Setup
```bash
# Clone repository
git clone https://github.com/frkndncr/WebAnalyzer.git
cd WebAnalyzer

# Install Python dependencies
pip install -r requirements.txt --break-system-packages

# Run setup script
chmod +x setup.sh
./setup.sh

# Verify installation
python main.py
```

### Advanced Configuration
```bash
# Create configuration file
python config.py --create-config

# Set API keys (optional)
export WHOIS_API_KEY="your_api_key"
python config.py --set-api-key "your_whois_api_key"

# Configure proxy support (optional)
python config.py --add-proxy "http://proxy:8080"
```

---

## 🎯 Usage

### Interactive Mode
```bash
python main.py
# Enter domain: example.com
# Select modules: A (All) or specific numbers
```

---

## 📋 Analysis Results

### Sample Output Structure
```json
{
  "domain": "example.com",
  "scan_timestamp": "2024-01-15 14:30:00",
  "modules_executed": 12,
  "risk_assessment": {
    "overall_grade": "B",
    "security_score": "78/100",
    "critical_findings": 0,
    "high_risk_findings": 2
  },
  "detailed_results": {
    "SEO Analysis": {
      "score": "85/100",
      "grade": "A",
      "load_time": "0.8s"
    },
    "API Security Scanner": {
      "vulnerabilities": 3,
      "risk_level": "High",
      "exploitation_possible": true
    }
  }
}
```

### Risk Scoring System
- **A Grade (90-100)**: Excellent security posture
- **B Grade (80-89)**: Good with minor improvements needed
- **C Grade (70-79)**: Moderate risk, attention required
- **D Grade (60-69)**: Poor security, immediate action needed
- **F Grade (0-59)**: Critical vulnerabilities present

---

## ⚠️ Legal & Ethical Usage

### Authorization Requirements
```
⚠️  LEGAL WARNING ⚠️
This tool contains aggressive security testing capabilities including:
- Vulnerability scanning and exploitation attempts
- Authentication bypass techniques  
- Injection attack vectors
- Rate limiting bypass methods

✅ AUTHORIZED USE ONLY
- Only use on systems you own
- Obtain explicit written permission before testing
- Respect rate limits and terms of service
- Follow responsible disclosure practices

❌ UNAUTHORIZED TESTING MAY BE ILLEGAL
```

### Responsible Disclosure
If you discover vulnerabilities using WebAnalyzer:
1. Report to the organization's security team
2. Allow reasonable time for patching
3. Follow coordinated disclosure timelines
4. Provide detailed technical information

---

## 🛡️ Security Features

### IP Rotation & Evasion
- **Dynamic Session Management**: Automatic IP and User-Agent rotation
- **Smart Delay Systems**: Randomized timing to avoid detection  
- **Rate Limit Detection**: Automatic adjustment based on server responses
- **Header Randomization**: Realistic browser fingerprinting

### Stealth Capabilities
- **Proxy Chain Support**: Multiple proxy server integration
- **Request Throttling**: Configurable delay ranges between requests
- **Error Recovery**: Automatic retry with different parameters
- **Fingerprint Avoidance**: Anti-detection techniques

---

## 📁 Project Structure

```
WebAnalyzer/
├── main.py                 # Main application entry point
├── config.py               # Configuration management
├── requirements.txt        # Python dependencies
├── setup.sh               # Installation script
├── modules/                # Directory containing all analysis modules
│   ├── domain_dns.py       # DNS record analysis module
│   ├── domain_info.py      # WHOIS information retrieval module
│   ├── seo_analysis.py     # SEO and analytics analysis module
│   ├── security_analysis.py# Security analysis module
│   ├── subfinder_tool.py   # Subdomain discovery module
│   ├── web_technologies.py # Web technology detection module
│   ├── subdomain_takeover.py # Subdomain takeover vulnerability detection module
│   ├── advanced_content_scanner.py # Advanced web content scanning module
│   ├── cloudflare_bypass.py # Cloudflare and WAF bypass module
│   ├── contact_spy.py      # Contact information discovery module
│   ├── nmap_zero_day.py    # Zero-day vulnerability scanning module
│   ├── api_security_scanner.py # Api vulnerability scanning module
├── utils/                 # Utility functions
│   ├── session_manager.py # IP rotation and session management
│   ├── module_wrapper.py  # Module execution framework
│   └── utils.py          # Helper functions
└── logs/                  # Analysis results and reports
```

---

## 🤝 Contributing

We welcome contributions from the cybersecurity community! Here's how you can help:

### Development Areas
- **New Analysis Modules**: API testing, mobile app analysis, cloud security
- **Evasion Techniques**: Advanced anti-detection methods
- **Reporting Features**: Better visualization and export options
- **Integration APIs**: Third-party security service integration
- **Performance Optimization**: Faster scanning and analysis

### Contribution Process
```bash
# Fork the repository
git fork https://github.com/frkndncr/WebAnalyzer.git

# Create feature branch
git checkout -b feature/new-analysis-module

# Make your changes and test
python -m pytest tests/

# Submit pull request with detailed description
```

### Development Guidelines
- Follow PEP 8 coding standards
- Add comprehensive documentation
- Include unit tests for new features
- Respect ethical hacking principles
- Consider legal implications

---

## 🔧 Advanced Configuration

### Environment Variables
```bash
export WHOIS_API_KEY="your_whois_api_key"
export WEBANALYZER_PROXY="http://proxy:8080"
export WEBANALYZER_DELAY="5-15"
export WEBANALYZER_USER_AGENTS="custom_ua_list.txt"
```

### Custom Module Development
```python
# Example custom module
from utils.module_wrapper import safe_module_execution

@safe_module_execution(delay_type='medium')
def custom_security_check(domain):
    """Custom security assessment module"""
    # Your analysis logic here
    return results
```

---

## 📊 Performance Metrics

- **Scanning Speed**: 10-50 endpoints per minute (depending on configuration)
- **Detection Rate**: 95%+ accuracy for common vulnerabilities
- **False Positive Rate**: <5% with advanced filtering
- **Resource Usage**: Low CPU, moderate network bandwidth
- **Stealth Rating**: High with proper configuration

---

## 📞 Support & Contact

### Professional Support
- **Security Consulting**: Advanced penetration testing services
- **Custom Development**: Tailored analysis modules
- **Training Services**: WebAnalyzer usage and development

### Community & Contact
- **Instagram**: [@f3rrkan](https://www.instagram.com/f3rrkan/)
- **LinkedIn**: [Furkan Dinçer](https://www.linkedin.com/in/furkan-dincer/)
- **Email**: hi@c4softwarestudio.com
- **Issues**: GitHub Issues for bug reports and feature requests

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

<div align="center">

**⭐ Star this repository if WebAnalyzer helped you in your security assessments!**

Made with ❤️ by [Furkan Dinçer](https://github.com/frkndncr) for the cybersecurity community

</div>