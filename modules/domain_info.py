import requests

def get_domain_info(domain, api_key):
    """
    It retrieves WHOIS information using WhoisXML API and other services and adds geographic information based on IP address.
    """
    whois_url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={api_key}&domainName={domain}&outputFormat=JSON"
    
    try:
        # Obtaining Whois information
        response = requests.get(whois_url)
        response.raise_for_status()
        data = response.json()

        # basic domain information
        domain_info = {
            "Domain": data.get("WhoisRecord", {}).get("domainName", "Unknown"),
            "Registrar Company (Registrar)": data.get("WhoisRecord", {}).get("registrarName", "Unknown"),
            "Creation Date": data.get("WhoisRecord", {}).get("createdDate", "Unknown"),
            "End Date": data.get("WhoisRecord", {}).get("expiresDate", "Unknown"),
            "Last Updated Date": data.get("WhoisRecord", {}).get("updatedDate", "Unknown"),
            "Domain Status": data.get("WhoisRecord", {}).get("status", ["Unknown"]),
        }

        # Additional functions
        domain_info["Privacy Protection"] = get_privacy_status(data)
        domain_info["DNSSEC Status"] = get_dnssec_status(domain)
        domain_info["SSL İnformation"] = get_ssl_info(domain)
        domain_info["Blacklist Check"] = get_blacklist_status(domain)

        # Physical Location and Server Information
        ip_address, location_info = get_location_info(domain)
        domain_info["IP Address"] = ip_address
        domain_info["Server Provider"] = location_info.get("org", "Unknown")
        domain_info["Physical Location"] = f"{location_info.get('city', 'Unknown')}, {location_info.get('country', 'Unknown')}"

        return domain_info
    except requests.exceptions.RequestException as e:
        return {"Error": f"An Error occurred during API request: {e}"}
    except KeyError:
        return {"Error": "The response format is not as expected."}


# Privacy Protection
def get_privacy_status(data):
    registrant_name = data.get("WhoisRecord", {}).get("registrant", {}).get("name", "")
    if "REDACTED" in registrant_name or "Privacy" in registrant_name:
        return "Effective"
    return "Inactive"

# DNSSEC Check
def get_dnssec_status(domain):
    try:
        url = f"https://dns.google/resolve?name={domain}&type=DNSKEY"
        response = requests.get(url)
        response.raise_for_status()
        dns_data = response.json()
        if dns_data.get("Answer"):
            return "Signed"
        return "Unsigned"
    except Exception as e:
        return f"Error: {e}"

# SSL İnformation
def get_ssl_info(domain):
    try:
        ssl_url = f"https://api.ssllabs.com/api/v3/analyze?host={domain}"
        response = requests.get(ssl_url)
        response.raise_for_status()
        ssl_data = response.json()

        if "endpoints" in ssl_data and ssl_data["endpoints"]:
            ssl_info = ssl_data["endpoints"][0]
            return {
                "IP Address": ssl_info.get("ipAddress", "Unknown"),
                "SSL Status": ssl_info.get("statusMessage", "Unknown"),
            }
        return "Failed to receive SSL information."
    except Exception as e:
        return f"Error: {e}"

# Blacklist check
def get_blacklist_status(domain):
    """VirusTotal API to check if the domain is blacklisted."""
    try:
        vt_api_key = "2440f34c350a618b99ecaad71ce096871f7ac5b96a4128371160147951c92860"
        vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": vt_api_key}
        response = requests.get(vt_url, headers=headers)
        response.raise_for_status()
        data = response.json()

        # Analiz sonuçlarını işleyin
        malicious = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
        suspicious = data["data"]["attributes"]["last_analysis_stats"]["suspicious"]
        if malicious > 0:
            return f"Blacklisted ({malicious} malicious report)"
        elif suspicious > 0:
            return f"Suspect ({suspicious} report)"
        else:
            return "Not on the blacklist"
    except Exception as e:
        return f"Unable to check: {e}"

# physical Location and Server Information
def get_location_info(domain):
    """
    Receives geographic information via IP address.
    """
    try:
        # Get IP address from record A
        dns_url = f"https://dns.google/resolve?name={domain}&type=A"
        response = requests.get(dns_url)
        response.raise_for_status()
        dns_data = response.json()
        ip_address = dns_data["Answer"][0]["data"]

        # IP Geolocation API
        geolocation_url = f"https://ipinfo.io/{ip_address}/json"
        geo_response = requests.get(geolocation_url)
        geo_response.raise_for_status()
        geo_data = geo_response.json()

        return ip_address, geo_data
    except Exception as e:
        return "Unknown", {}