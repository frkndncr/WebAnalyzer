import os
import subprocess
import requests
import re
import concurrent.futures

def run_passive_subdomain_discovery(domain):
    """
    Keyless passive OSINT subdomain discovery engine.
    Queries crt.sh, HackerTarget, and AlienVault OTX.
    """
    print(f"[*] Subfinder missing. Running keyless custom OSINT fallback for: {domain}...")
    subdomains = set()
    
    # Helper to clean and validate subdomain names
    def clean_name(name):
        name = name.strip().lower()
        if name.startswith('*.'):
            name = name[2:]
        return name
        
    # 1. Query crt.sh (Certificate Transparency logs)
    def fetch_crt_sh():
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    for name in name_value.split('\n'):
                        name = clean_name(name)
                        if name.endswith(domain) and name != domain:
                            subdomains.add(name)
        except Exception:
            pass

    # 2. Query HackerTarget Hostsearch API
    def fetch_hackertarget():
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            response = requests.get(url, timeout=10)
            if response.status_code == 200 and "error" not in response.text:
                for line in response.text.splitlines():
                    parts = line.split(',')
                    if parts:
                        name = clean_name(parts[0])
                        if name.endswith(domain) and name != domain:
                            subdomains.add(name)
        except Exception:
            pass

    # 3. Query AlienVault OTX API
    def fetch_alienvault():
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for record in data.get('passive_dns', []):
                    name = clean_name(record.get('hostname', ''))
                    if name.endswith(domain) and name != domain:
                        subdomains.add(name)
        except Exception:
            pass

    # Run passive queries concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        executor.map(lambda f: f(), [fetch_crt_sh, fetch_hackertarget, fetch_alienvault])
        
    return sorted(list(subdomains))

def run_subfinder(domain, logs_dir="logs"):
    """
    Runs subfinder, saves the subdomains in the logs directory, and returns the total list.
    If subfinder is missing, falls back to custom keyless OSINT discovery.
    - domain: Target domain for discovering subdomains.
    - logs_dir: Directory to save the subdomains.
    """
    try:
        # Create the logs directory if it doesn't exist
        if not os.path.exists(logs_dir):
            os.makedirs(logs_dir)

        # Check if domain directory exists inside logs
        domain_dir = os.path.join(logs_dir, domain)
        if not os.path.exists(domain_dir):
            os.makedirs(domain_dir)

        # Output file path
        output_file = os.path.join(domain_dir, f"{domain}-sub.txt")

        subdomains = []
        try:
            # Run Subfinder
            result = subprocess.run(
                ["subfinder", "-d", domain],
                capture_output=True,
                text=True,
                check=True
            )
            # Process subfinder output
            subdomains = result.stdout.splitlines()
        except (FileNotFoundError, subprocess.CalledProcessError):
            # Fallback to keyless custom passive OSINT
            subdomains = run_passive_subdomain_discovery(domain)

        # Save results to the output file
        with open(output_file, "w") as file:
            file.write("\n".join(subdomains))

        print(f"Subdomains saved to: {output_file}")
        return subdomains
    except Exception as e:
        print(f"Error: Failed to run subdomain discovery: {e}")
        return []