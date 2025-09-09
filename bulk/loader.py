import csv
import json
from pathlib import Path
import logging
from database.db_manager import db_manager

class BulkDomainLoader:
    def __init__(self):
        self.db = db_manager
        self.supported_formats = ['.txt', '.csv', '.json']
    
    def load_domains(self, file_path, job_name=None):
        """Domain listesini yükle"""
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        extension = file_path.suffix.lower()
        
        if extension not in self.supported_formats:
            raise ValueError(f"Unsupported format. Use: {self.supported_formats}")
        
        # Domain listesini oku
        domains = self._read_file(file_path, extension)
        
        # Validate ve clean
        domains = self._validate_domains(domains)
        
        if not domains:
            raise ValueError("No valid domains found in file")
        
        # Database'e kaydet
        job_name = job_name or f"Bulk Scan - {file_path.name}"
        job_id = self._create_job(job_name, len(domains))
        
        # Domainleri ekle
        added = self.db.add_domains_bulk(job_id, domains)
        
        logging.info(f"Job #{job_id} created: {added}/{len(domains)} domains added")
        
        return job_id, added
    
    def _read_file(self, file_path, extension):
        """Dosyadan domainleri oku"""
        domains = []
        
        try:
            if extension == '.txt':
                with open(file_path, 'r', encoding='utf-8') as f:
                    domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    
            elif extension == '.csv':
                with open(file_path, 'r', encoding='utf-8') as f:
                    reader = csv.reader(f)
                    # Skip header if exists
                    first_row = next(reader, None)
                    if first_row and not self._is_domain(first_row[0]):
                        pass  # Skip header
                    else:
                        domains.append(first_row[0].strip())
                    
                    for row in reader:
                        if row and row[0].strip():
                            domains.append(row[0].strip())
                            
            elif extension == '.json':
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        # Handle different JSON formats
                        for item in data:
                            if isinstance(item, dict):
                                domain = (item.get('domain_name') or 
                                         item.get('domain') or 
                                         item.get('url', ''))
                                if domain:
                                    domains.append(domain)
                            elif isinstance(item, str):
                                domains.append(item)
                    elif isinstance(data, dict) and 'domains' in data:
                        domains = data['domains']
                        
        except Exception as e:
            raise ValueError(f"Error reading file: {e}")
        
        return domains
    
    def _validate_domains(self, domains):
        """Domain validasyonu"""
        clean_domains = []
        
        for domain in domains:
            # Temizle
            domain = str(domain).strip().lower()
            
            # http/https kaldır
            domain = domain.replace('http://', '').replace('https://', '')
            
            # Path kaldır
            if '/' in domain:
                domain = domain.split('/')[0]
            
            # Port kaldır
            if ':' in domain and not domain.count(':') > 1:  # IPv6 değilse
                domain = domain.split(':')[0]
            
            # Basic validation
            if self._is_domain(domain):
                clean_domains.append(domain)
        
        # Duplicate'leri kaldır
        return list(set(clean_domains))
    
    def _is_domain(self, domain):
        """Domain format validation"""
        if not domain or len(domain) < 4:
            return False
        
        # Basic domain pattern check
        if not '.' in domain:
            return False
        
        # Check for invalid characters
        invalid_chars = ['<', '>', '"', "'", '|', '\\', '^', '`', '{', '}']
        if any(char in domain for char in invalid_chars):
            return False
        
        # Check domain parts
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        # Check if all parts are valid
        for part in parts:
            if not part or part.startswith('-') or part.endswith('-'):
                return False
        
        return True
    
    def _create_job(self, job_name, total_domains):
        """Yeni job oluştur"""
        try:
            return self.db.create_scan_job(job_name, total_domains)
        except Exception as e:
            raise RuntimeError(f"Failed to create scan job: {e}")