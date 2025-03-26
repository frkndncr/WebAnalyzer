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
├── socket.py               # Socket server implementation for remote access
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
│   ├── cloudflare_bypass.py # Cloudflare and WAF bypass module
│   ├── contact_spy.py      # Contact information discovery module
│   ├── nmap_zero_day.py    # Zero-day vulnerability scanning module
└── tests/                  # Test scripts for the project
    └── test_main.py        # Unit tests for main.py
```

---

## Example Output Screenshot

![image](https://github.com/user-attachments/assets/09c9912b-55dd-448a-91d5-544fd92baede)


---
## 🤝 Contributing to Web Analyzer Tool

We welcome contributions from the community to make the Web Analyzer Tool even more powerful and effective! This guide will help you understand how you can contribute to the project.

### Ways to Contribute

1. **Reporting Bugs**: If you encounter any issues while using the tool, please open an issue with:
   - A clear description of the bug
   - Steps to reproduce the issue
   - Your environment details (OS, Python version, etc.)
   - Error messages or screenshots if applicable

2. **Feature Requests**: Have an idea to enhance the tool? Open an issue describing:
   - The feature you'd like to see
   - How it would benefit users
   - Any implementation ideas you might have

3. **Code Contributions**: Want to write code for the project? Here's how:

### Development Workflow

1. **Fork the Repository**:
   - Click the "Fork" button at the top of this repository
   - Clone your fork locally: `git clone https://github.com/YOUR_USERNAME/web-analyzer-tool.git`

2. **Set Up Your Environment**:
   ```bash
   cd web-analyzer-tool
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   pip install -e .  # Install the package in development mode
   ```

3. **Create a Branch**:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b bugfix/issue-you-are-fixing
   ```

4. **Make Your Changes**:
   - Follow the project's coding style and conventions
   - Add comprehensive comments and docstrings
   - Write clear, descriptive commit messages

5. **Write/Update Tests**:
   - Add tests for new features
   - Ensure existing tests pass with your changes

6. **Submit a Pull Request**:
   - Push your changes to your fork: `git push origin feature/your-feature-name`
   - Create a pull request from your fork to the main repository
   - Provide a clear description of your changes and reference any related issues

### Development Guidelines

- **Code Style**: Follow PEP 8 standards and the existing code style in the project
- **Documentation**: Document all functions, classes, and complex logic
- **Modularity**: Keep functions focused on a single task
- **Error Handling**: Implement proper error handling and provide informative error messages
- **Security**: Be mindful of security implications, especially when handling sensitive information
- **Dependencies**: Minimize external dependencies; justify any new ones

### Ideas for Contributions

- **New Analysis Modules**: Add support for additional types of web analysis
- **Performance Optimizations**: Improve scan speed and resource usage
- **Reporting Enhancements**: Create better visualization and export options for analysis results
- **API Integration**: Add integrations with relevant security or SEO APIs
- **Detection Rules**: Expand the ruleset for detecting technologies, vulnerabilities, etc.
- **User Interface**: Improve CLI experience or develop a web interface
- **Documentation**: Enhance user and developer documentation
- **Internationalization**: Add support for multiple languages

### Code Review Process

- All pull requests will be reviewed by project maintainers
- Feedback may be provided for necessary changes
- Once approved, your contribution will be merged into the main codebase

We value all contributions and will ensure proper credit is given to contributors. Thank you for helping improve the Web Analyzer Tool!

---
## License
This project is licensed under the MIT License.
## Contact
- İnstagram: https://www.instagram.com/f3rrkan/
- LinkedIn: https://www.linkedin.com/in/furkan-dincer/
- Mail: hi@c4softwarestudio.com
---
