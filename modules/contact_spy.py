# modules/contact_spy.py - Enhanced contact information scraper with proper validation
import re
import json
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Set
from datetime import datetime
import logging
import os

class GlobalDomainScraper:
    def __init__(self, domain: str, max_pages: int = 10, log_dir: str = "logs"):
        self.domain = domain
        self.max_pages = max_pages
        self.visited_urls = set()
        self.session = self._setup_session()
        self.seen_profiles = set()  # Track unique social media profiles
        
        # Setup logging
        os.makedirs(log_dir, exist_ok=True)
        self.logger = logging.getLogger(f'contact_spy_{domain}')
        self.logger.setLevel(logging.WARNING)  # Reduce log noise
        if not self.logger.handlers:
            handler = logging.FileHandler(f"{log_dir}/contact_{domain}.log")
            handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
            self.logger.addHandler(handler)
        
        # Enhanced patterns
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        self.phone_pattern = re.compile(r'[\+]?[\d\s\-\(\)\.]{8,20}')
        
        # Social media patterns (excluding share buttons and common false positives)
        self.social_patterns = {
            'Facebook': re.compile(r'facebook\.com/(?!sharer|dialog|plugins)([a-zA-Z0-9._-]+)(?!/|\?|&)', re.I),
            'Twitter': re.compile(r'(?:twitter\.com|x\.com)/(?!share|intent|home)([a-zA-Z0-9._-]+)(?!/|\?|&)', re.I),
            'Instagram': re.compile(r'instagram\.com/(?!p/|explore|accounts)([a-zA-Z0-9._-]+)(?!/|\?|&)', re.I),
            'LinkedIn': re.compile(r'linkedin\.com/(?:in|company)/([a-zA-Z0-9._-]+)(?!/|\?|&)', re.I),
            'YouTube': re.compile(r'youtube\.com/(?:channel/|user/|c/|@)([a-zA-Z0-9._-]+)(?!/|\?|&)', re.I),
            'GitHub': re.compile(r'github\.com/([a-zA-Z0-9._-]+)(?!/|\?|&|\.git)', re.I),
            'TikTok': re.compile(r'tiktok\.com/@([a-zA-Z0-9._-]+)(?!/|\?|&)', re.I)
        }

    def _setup_session(self) -> requests.Session:
        """Setup HTTP session with headers"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        })
        session.verify = False
        return session

    def _is_valid_url(self, url: str, base_domain: str) -> bool:
        """Check if URL is valid and belongs to domain"""
        try:
            parsed = urlparse(url)
            # Must be same domain or subdomain
            if not (base_domain in parsed.netloc.lower() or parsed.netloc.lower().endswith('.' + base_domain)):
                return False
            # Skip files and assets
            skip_extensions = ['.pdf', '.jpg', '.png', '.gif', '.zip', '.doc', '.mp4', '.css', '.js']
            if any(url.lower().endswith(ext) for ext in skip_extensions):
                return False
            # Skip asset directories
            skip_dirs = ['/assets/', '/images/', '/css/', '/js/', '/fonts/', '/media/']
            if any(skip_dir in url.lower() for skip_dir in skip_dirs):
                return False
            return True
        except:
            return False

    def _extract_emails(self, text: str) -> Set[str]:
        """Extract email addresses from text with enhanced validation"""
        emails = set()
        matches = self.email_pattern.findall(text)
        for email in matches:
            email = email.lower().strip()
            # Filter out common false positives and invalid emails
            if not any(skip in email for skip in [
                'example.', 'test@', 'noreply@', 'no-reply@', 'admin@example',
                'user@example', 'email@example', 'name@example', '.jpg@', '.png@'
            ]) and len(email) > 5 and email.count('@') == 1:
                emails.add(email)
        return emails

    def _extract_phones(self, text: str) -> Set[str]:
        """Extract phone numbers from text with enhanced validation"""
        phones = set()
        matches = self.phone_pattern.findall(text)
        for phone in matches:
            # Clean phone number
            clean_phone = re.sub(r'[^\d+]', '', phone)
            
            # Enhanced validation
            if self._is_valid_phone(clean_phone):
                # Format for display
                if clean_phone.startswith('+'):
                    phones.add(clean_phone)
                elif len(clean_phone) >= 10:
                    phones.add(clean_phone)
                    
        return phones

    def _is_valid_phone(self, phone: str) -> bool:
        """Validate phone number with strict rules"""
        # Remove + for length check
        digits_only = phone.replace('+', '')
        
        # Must be 7-15 digits
        if not (7 <= len(digits_only) <= 15):
            return False
            
        # Must be all digits
        if not digits_only.isdigit():
            return False
            
        # Exclude common false positives
        false_positives = [
            # Date patterns
            r'^(19|20)\d{6,8}$',  # Years 1900-2099 + additional digits
            r'^(0[1-9]|[12][0-9]|3[01])(0[1-9]|1[0-2])\d{4,6}$',  # Date formats
            # Repeating patterns
            r'^(\d)\1{6,}$',  # Same digit repeated 7+ times
            r'^(01|10|11|12|21|22|23)\1+$',  # Simple patterns repeated
            # Common sequences
            r'^(123|456|789|987|654|321){2,}$',  # Sequential numbers
            # Version numbers and IDs
            r'^[1-9]\d{0,2}(\d{4}){1,2}$',  # Version-like patterns
        ]
        
        for pattern in false_positives:
            if re.match(pattern, digits_only):
                return False
                
        return True

    def _extract_social_media(self, text: str, source_url: str) -> List[Dict]:
        """Extract social media profiles with duplicate prevention and validation"""
        profiles = []
        
        for platform, pattern in self.social_patterns.items():
            matches = pattern.finditer(text)
            for match in matches:
                try:
                    username = match.group(1)
                    full_match = match.group(0)
                    
                    # Validate username
                    if not self._is_valid_social_username(username, platform):
                        continue
                        
                    # Create unique identifier
                    profile_id = f"{platform}:{username.lower()}"
                    
                    if profile_id not in self.seen_profiles:
                        self.seen_profiles.add(profile_id)
                        
                        # Ensure proper URL format
                        if not full_match.startswith('http'):
                            full_match = f"https://{full_match}"
                        
                        profiles.append({
                            'platform': platform,
                            'username': username,
                            'url': full_match,
                            'found_on': source_url
                        })
                except Exception as e:
                    self.logger.debug(f"Error processing social media match: {e}")
                    continue
                    
        return profiles

    def _is_valid_social_username(self, username: str, platform: str) -> bool:
        """Validate social media username"""
        if not username or len(username) < 2:
            return False
            
        # Common invalid usernames/paths
        invalid_usernames = {
            'share', 'sharer', 'intent', 'oauth', 'login', 'register', 'signup',
            'api', 'www', 'mobile', 'm', 'help', 'support', 'about', 'privacy',
            'terms', 'contact', 'home', 'index', 'main', 'page', 'site',
            'web', 'app', 'download', 'install', 'get', 'go', 'redirect',
            'link', 'url', 'http', 'https', 'com', 'org', 'net'
        }
        
        if username.lower() in invalid_usernames:
            return False
            
        # Platform-specific validation
        platform_rules = {
            'Twitter': lambda u: len(u) <= 15 and not u.startswith('_'),
            'Instagram': lambda u: len(u) <= 30,
            'LinkedIn': lambda u: len(u) <= 100,
            'GitHub': lambda u: len(u) <= 39 and not u.startswith('-'),
            'YouTube': lambda u: len(u) <= 100,
            'Facebook': lambda u: len(u) <= 50,
            'TikTok': lambda u: len(u) <= 24
        }
        
        rule = platform_rules.get(platform)
        if rule and not rule(username):
            return False
            
        return True

    def _scrape_page(self, url: str) -> Dict:
        """Scrape a single page for contact information"""
        try:
            response = self.session.get(url, timeout=15)
            if response.status_code != 200:
                return None
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Remove script and style elements
            for element in soup(['script', 'style', 'noscript']):
                element.decompose()
            
            # Get text content
            text = soup.get_text(separator=' ', strip=True)
            
            # Also check href attributes for social media
            all_links = ' '.join([a.get('href', '') for a in soup.find_all('a', href=True)])
            full_text = f"{text} {all_links}"
            
            # Extract information
            emails = self._extract_emails(full_text)
            phones = self._extract_phones(text)
            social_media = self._extract_social_media(full_text, url)
            
            # Only return if we found something
            if emails or phones or social_media:
                return {
                    'url': url,
                    'emails': list(emails),
                    'phones': list(phones), 
                    'social_media': social_media
                }
            
        except Exception as e:
            self.logger.error(f"Error scraping {url}: {str(e)}")
        
        return None

    def _get_page_links(self, url: str) -> Set[str]:
        """Get internal links from a page"""
        links = set()
        try:
            response = self.session.get(url, timeout=15)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for a_tag in soup.find_all('a', href=True):
                link = a_tag['href']
                absolute_link = urljoin(url, link)
                
                if self._is_valid_url(absolute_link, self.domain):
                    links.add(absolute_link)
                    
        except Exception as e:
            self.logger.error(f"Error getting links from {url}: {str(e)}")
        
        return links

    def crawl(self) -> Dict:
        """Main crawling function"""
        start_url = f"https://{self.domain}"
        urls_to_visit = {start_url}
        page_results = []
        all_emails = set()
        all_phones = set()
        all_social_media = []
        
        self.logger.info(f"Starting crawl of {self.domain}")
        
        while urls_to_visit and len(self.visited_urls) < self.max_pages:
            current_url = urls_to_visit.pop()
            
            if current_url in self.visited_urls:
                continue
                
            self.visited_urls.add(current_url)
            self.logger.info(f"Scraping: {current_url}")
            
            # Scrape current page
            page_data = self._scrape_page(current_url)
            if page_data:
                page_results.append(page_data)
                all_emails.update(page_data['emails'])
                all_phones.update(page_data['phones'])
                all_social_media.extend(page_data['social_media'])
            
            # Get new links to visit
            if len(self.visited_urls) < self.max_pages:
                new_links = self._get_page_links(current_url)
                urls_to_visit.update(new_links - self.visited_urls)
        
        # Prepare results
        results = {
            'domain': self.domain,
            'scan_date': datetime.now().isoformat(),
            'pages_scanned': len(self.visited_urls),
            'summary': {
                'total_emails': len(all_emails),
                'total_phones': len(all_phones),
                'total_social_media': len(all_social_media),
                'unique_emails': list(all_emails),
                'unique_phones': list(all_phones)
            },
            'page_results': page_results,
            'social_media_by_platform': self._group_social_media(all_social_media)
        }
        
        self.logger.info(f"Crawl completed. Found {len(all_emails)} emails, {len(all_phones)} phones, {len(all_social_media)} social profiles")
        return results

    def _group_social_media(self, profiles: List[Dict]) -> Dict:
        """Group social media profiles by platform"""
        grouped = {}
        for profile in profiles:
            platform = profile['platform']
            if platform not in grouped:
                grouped[platform] = []
            grouped[platform].append(profile)
        return grouped

    def export_results(self, results: Dict, output_format: str = 'json'):
        """Export results to file"""
        try:
            output_dir = f"logs/{self.domain}"
            os.makedirs(output_dir, exist_ok=True)
            
            if output_format.lower() == 'json':
                filename = f"{output_dir}/contact_scan.json"
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(results, f, indent=2, ensure_ascii=False, default=str)
                self.logger.info(f"Results exported to {filename}")
                
        except Exception as e:
            self.logger.error(f"Export failed: {str(e)}")

# Simple usage function for backward compatibility
def main(domain: str, max_pages: int = 10) -> Dict:
    """Simple main function"""
    scraper = GlobalDomainScraper(domain, max_pages)
    results = scraper.crawl()
    scraper.export_results(results)
    return results