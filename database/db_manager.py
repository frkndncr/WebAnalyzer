import mysql.connector
from mysql.connector import Error, pooling
import json
from datetime import datetime
import logging
from typing import List, Dict, Any, Optional
import time

class DatabaseManager:
    def __init__(self):
        self.config = {
            'host': '89.116.147.52',
            'database': 'u671547123_webanalyzer',
            'user': 'u671547123_webcijojuk',
            'password': 'D@i7F2!Q2',
            'pool_name': 'webanalyzer_pool',
            'pool_size': 3,
            'connection_timeout': 60,
            'pool_reset_session': False,
            'charset': 'utf8mb4',
            'use_unicode': True,
            'autocommit': False
        }
        
        try:
            self.pool = mysql.connector.pooling.MySQLConnectionPool(**self.config)
            logging.info("Database connection pool created successfully")
        except Error as e:
            logging.error(f"Error creating connection pool: {e}")
            raise
    
    def get_connection(self):
        """Connection pool'dan bağlantı al - retry logic"""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                conn = self.pool.get_connection()
                return conn
            except Error as e:
                if "max_connections" in str(e):
                    logging.warning(f"Connection limit hit, waiting... (attempt {attempt + 1})")
                    time.sleep(30)  # 30 saniye bekle
                    continue
                if attempt == max_retries - 1:
                    raise
                time.sleep(2)  # Kısa bekleme süresi
    
    def execute_query(self, query: str, params=None, commit: bool = True, batch: bool = False):
        """Query çalıştır - batch support eklendi"""
        connection = None
        cursor = None
        try:
            connection = self.get_connection()
            cursor = connection.cursor(dictionary=True)
            
            if batch and params and isinstance(params, list):
                # Batch execution
                cursor.executemany(query, params)
            else:
                cursor.execute(query, params or ())
            
            if commit:
                connection.commit()
                if batch:
                    return cursor.rowcount
                else:
                    return cursor.lastrowid
            else:
                return cursor.fetchall()
                
        except Error as e:
            logging.error(f"Database query error: {e}")
            if connection:
                connection.rollback()
            raise
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()
    
    def execute_batch_query(self, query: str, params_list: List[tuple]):
        """Batch query execution"""
        return self.execute_query(query, params_list, commit=True, batch=True)
    
    def create_scan_job(self, job_name: str, total_domains: int) -> int:
        """Yeni tarama işi oluştur"""
        query = """
            INSERT INTO scan_jobs (job_name, total_domains, status, created_at)
            VALUES (%s, %s, 'pending', NOW())
        """
        return self.execute_query(query, (job_name, total_domains))
    
    def add_domains_bulk(self, job_id: int, domains: List[str]) -> int:
        """Toplu domain ekleme - schema uyumlu"""
        if not domains:
            return 0
            
        # Mevcut schema ile uyumlu query
        query = """
            INSERT INTO domains (job_id, domain, status, priority)
            VALUES (%s, %s, 'pending', 5)
            ON DUPLICATE KEY UPDATE 
            job_id = VALUES(job_id),
            status = 'pending'
        """
        
        connection = self.get_connection()
        cursor = connection.cursor()
        
        try:
            data = [(job_id, domain.strip().lower()) for domain in domains if domain.strip()]
            cursor.executemany(query, data)
            connection.commit()
            return cursor.rowcount
        except Error as e:
            connection.rollback()
            logging.error(f"Bulk domain insert failed: {e}")
            raise
        finally:
            cursor.close()
            connection.close()

    def get_pending_domains(self, job_id: int, limit: int = 100) -> List[Dict]:
        """Taranacak domainleri al"""
        query = """
            SELECT id, domain FROM domains
            WHERE job_id = %s AND status = 'pending'
            ORDER BY priority DESC, id ASC
            LIMIT %s
        """
        return self.execute_query(query, (job_id, limit), commit=False)
    
    def update_domain_status(self, domain_id: int, status: str):
        """Domain durumunu güncelle"""
        query = """
            UPDATE domains 
            SET status = %s, 
                scanned_at = CASE WHEN %s IN ('completed', 'failed', 'timeout') THEN NOW() ELSE scanned_at END,
                updated_at = NOW()
            WHERE id = %s
        """
        self.execute_query(query, (status, status, domain_id))
    
    def batch_update_domain_status(self, updates: List[tuple]):
        """Batch domain status update"""
        if not updates:
            return
            
        query = """
            UPDATE domains 
            SET status = %s
            WHERE id = %s
        """
        self.execute_batch_query(query, updates)

    def _update_job_stats(self, stats):
        """İstatistikleri güncelle - schema uyumlu"""
        try:
            job_stats = self.db.get_job_statistics(self.job_id)
            
            # Sadece mevcut kolonları kullan
            self.db.execute_query("""
                UPDATE scan_jobs 
                SET completed_domains = %s
                WHERE id = %s
            """, (job_stats['completed'], self.job_id))
            
        except Exception as e:
            logging.error(f"Failed to update stats: {e}")
            
    def save_scan_result(self, domain_id: int, module_name: str, result_data: Dict, 
                        risk_level: str, score: int, execution_time: float):
        """Tarama sonucunu kaydet - optimize edildi"""
        
        # Large result data için size kontrolü
        serialized_data = json.dumps(result_data, ensure_ascii=False)
        
        # 64KB'den büyükse compress veya truncate
        if len(serialized_data.encode('utf-8')) > 65535:
            # Sadece critical bilgileri sakla
            critical_data = self._extract_critical_data(result_data, module_name)
            serialized_data = json.dumps(critical_data, ensure_ascii=False)
            logging.warning(f"Large result data truncated for domain_id {domain_id}, module {module_name}")
        
        query = """
            INSERT INTO scan_results 
            (domain_id, module_name, status, risk_level, score, execution_time, result_data, created_at)
            VALUES (%s, %s, 'completed', %s, %s, %s, %s, NOW())
            ON DUPLICATE KEY UPDATE
            status = VALUES(status),
            risk_level = VALUES(risk_level),
            score = VALUES(score),
            execution_time = VALUES(execution_time),
            result_data = VALUES(result_data),
            updated_at = NOW()
        """
        
        self.execute_query(
            query,
            (domain_id, module_name, risk_level, score, execution_time, serialized_data)
        )
    
    def save_technology(self, domain_id: int, category: str, name: str, version: str = None, confidence: int = 100):
        """Teknoloji tespitini kaydet"""
        query = """
            INSERT INTO technologies 
            (domain_id, category, name, version, confidence, detected_at)
            VALUES (%s, %s, %s, %s, %s, NOW())
        """
        self.execute_query(query, (domain_id, category, name, version, confidence))

    def save_technologies_bulk(self, domain_id: int, technologies: List[Dict]):
        """Toplu teknoloji kaydetme"""
        if not technologies:
            return
            
        query = """
            INSERT INTO technologies 
            (domain_id, category, name, version, confidence, detected_at)
            VALUES (%s, %s, %s, %s, %s, NOW())
        """
        
        data = []
        for tech in technologies:
            data.append((
                domain_id,
                tech.get('category', 'unknown'),
                tech.get('name', ''),
                tech.get('version', None),
                tech.get('confidence', 100)
            ))
        
        if data:
            self.execute_batch_query(query, data)

    def save_vulnerabilities_from_result(self, domain_id: int, module_name: str, result_data: Dict):
        """Tarama sonucundan zafiyetleri çıkar ve kaydet"""
        vulnerabilities = []
        
        if module_name == "security_analysis":
            # Security analysis sonuçlarından zafiyet çıkar
            if result_data.get("vulnerabilities_found", 0) > 0:
                vulns = result_data.get("vulnerabilities", [])
                for vuln in vulns:
                    vulnerabilities.append({
                        'type': vuln.get('type', 'unknown'),
                        'severity': vuln.get('severity', 'low').lower(),
                        'details': vuln
                    })
            
            # Missing headers da zafiyet sayılabilir
            missing_headers = result_data.get("missing_critical_headers", [])
            for header in missing_headers:
                vulnerabilities.append({
                    'type': 'missing_security_header',
                    'severity': 'medium',
                    'details': {'header': header, 'description': f'Missing {header} header'}
                })
        
        elif module_name == "web_technologies":
            # WordPress security risks
            if result_data.get("is_wordpress", False):
                wp_risk = result_data.get("wp_security_risk", "").lower()
                if wp_risk in ["high", "critical"]:
                    vulnerabilities.append({
                        'type': 'wordpress_security_risk',
                        'severity': wp_risk,
                        'details': {
                            'wp_version': result_data.get("wp_version"),
                            'users_found': result_data.get("wp_users_count", 0),
                            'plugins_count': result_data.get("wp_plugins_count", 0)
                        }
                    })
        
        # Zafiyetleri kaydet
        for vuln in vulnerabilities:
            self.save_vulnerability(
                domain_id,
                vuln['type'],
                vuln['severity'],
                module_name,
                vuln['details']
            )

    def update_job_statistics_auto(self, job_id: int):
        """Job istatistiklerini otomatik hesapla ve statistics tablosuna kaydet"""
        
        # Mevcut istatistikleri hesapla
        stats = self.get_job_statistics(job_id)
        
        # Vulnerability count
        vuln_query = """
            SELECT COUNT(*) as vuln_count
            FROM vulnerabilities v
            JOIN domains d ON v.domain_id = d.id
            WHERE d.job_id = %s
        """
        vuln_result = self.execute_query(vuln_query, (job_id,), commit=False)
        total_vulns = vuln_result[0]['vuln_count'] if vuln_result else 0
        
        # Average scan time
        time_query = """
            SELECT AVG(execution_time) as avg_time
            FROM scan_results sr
            JOIN domains d ON sr.domain_id = d.id
            WHERE d.job_id = %s AND sr.execution_time > 0
        """
        time_result = self.execute_query(time_query, (job_id,), commit=False)
        avg_time = float(time_result[0]['avg_time'] or 0) if time_result else 0
        
        # Risk distribution
        risk_query = """
            SELECT 
                risk_level,
                COUNT(*) as count
            FROM scan_results sr
            JOIN domains d ON sr.domain_id = d.id
            WHERE d.job_id = %s
            GROUP BY risk_level
        """
        risk_results = self.execute_query(risk_query, (job_id,), commit=False)
        risk_distribution = {r['risk_level']: r['count'] for r in risk_results}
        
        # Success rate
        total_scanned = stats['completed'] + stats['failed']
        success_rate = (stats['completed'] / max(total_scanned, 1)) * 100
        
        # Statistics tablosuna kaydet veya güncelle
        stats_query = """
            INSERT INTO statistics 
            (job_id, total_scanned, total_vulnerabilities, avg_scan_time, success_rate, 
            risk_distribution, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, NOW())
            ON DUPLICATE KEY UPDATE
            total_scanned = VALUES(total_scanned),
            total_vulnerabilities = VALUES(total_vulnerabilities),
            avg_scan_time = VALUES(avg_scan_time),
            success_rate = VALUES(success_rate),
            risk_distribution = VALUES(risk_distribution),
            created_at = NOW()
        """
        
        self.execute_query(stats_query, (
            job_id,
            total_scanned,
            total_vulns,
            avg_time,
            success_rate,
            json.dumps(risk_distribution, ensure_ascii=False)
        ))

    def log_scan_activity(self, domain_id: int, level: str, message: str, module_name: str = None):
        """Scan aktivitesini logla"""
        query = """
            INSERT INTO scan_logs 
            (domain_id, log_level, message, module_name, created_at)
            VALUES (%s, %s, %s, %s, NOW())
        """
        self.execute_query(query, (domain_id, level, message, module_name))

    def _extract_critical_data(self, result_data: Dict, module_name: str) -> Dict:
        """Large result data'dan critical bilgileri çıkar"""
        critical_data = {
            "status": result_data.get("status"),
            "domain": result_data.get("domain"),
            "execution_time": result_data.get("execution_time"),
            "module": module_name
        }
        
        # Module-specific critical data
        if module_name == "security_analysis":
            critical_data.update({
                "security_score": result_data.get("security_score"),
                "security_grade": result_data.get("security_grade"),
                "risk_level": result_data.get("risk_level"),
                "waf_detected": result_data.get("waf_detected"),
                "ssl_grade": result_data.get("ssl_grade"),
                "vulnerabilities_found": result_data.get("vulnerabilities_found")
            })
        elif module_name == "web_technologies":
            critical_data.update({
                "technologies": result_data.get("technologies", [])[:10],  # First 10
                "security_score": result_data.get("security_score"),
                "is_wordpress": result_data.get("is_wordpress"),
                "wp_users_count": result_data.get("wp_users_count"),
                "cms_detected": result_data.get("cms_detected")
            })
        elif module_name == "domain_info":
            critical_data.update({
                "registrar": result_data.get("Registrar Company (Registrar)"),
                "creation_date": result_data.get("Creation Date"),
                "expiry_date": result_data.get("End Date")
            })
        
        return critical_data
    
    def save_vulnerability(self, domain_id: int, vuln_type: str, severity: str, 
                          module_name: str, details: Dict):
        """Zafiyet kaydet"""
        query = """
            INSERT INTO vulnerabilities
            (domain_id, vulnerability_type, severity, module_name, details, created_at)
            VALUES (%s, %s, %s, %s, %s, NOW())
        """
        
        if isinstance(details, dict):
            details = json.dumps(details, ensure_ascii=False)
            
        self.execute_query(query, (domain_id, vuln_type, severity, module_name, details))
    
    def get_job_statistics(self, job_id: int) -> Dict:
        """İş istatistiklerini al"""
        query = """
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
                SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
                SUM(CASE WHEN status = 'scanning' THEN 1 ELSE 0 END) as scanning,
                SUM(CASE WHEN status = 'skipped' THEN 1 ELSE 0 END) as skipped
            FROM domains
            WHERE job_id = %s
        """
        result = self.execute_query(query, (job_id,), commit=False)[0]
        
        # Calculate progress percentage
        total = result['total']
        completed = result['completed'] + result['failed'] + result['skipped']
        result['progress'] = (completed / max(total, 1)) * 100
        
        return result
    
    def get_all_jobs(self) -> List[Dict]:
        """Tüm job'ları listele"""
        query = """
            SELECT 
                sj.id,
                sj.job_name as name,
                sj.status,
                sj.total_domains as domain_count,
                sj.created_at as created_date,
                COUNT(d.id) as actual_domains,
                SUM(CASE WHEN d.status = 'completed' THEN 1 ELSE 0 END) as completed_domains
            FROM scan_jobs sj
            LEFT JOIN domains d ON sj.id = d.job_id
            GROUP BY sj.id, sj.job_name, sj.status, sj.total_domains, sj.created_at
            ORDER BY sj.created_at DESC
            LIMIT 50
        """
        return self.execute_query(query, commit=False)
    
    def get_recent_scan_results(self, job_id: int, limit: int = 10) -> List[Dict]:
        """Son tarama sonuçlarını al"""
        query = """
            SELECT 
                d.domain,
                sr.module_name,
                sr.status,
                sr.risk_level,
                sr.score,
                sr.created_at as scan_date
            FROM scan_results sr
            JOIN domains d ON sr.domain_id = d.id
            WHERE d.job_id = %s
            ORDER BY sr.created_at DESC
            LIMIT %s
        """
        return self.execute_query(query, (job_id, limit), commit=False)
    
    def cleanup_old_results(self, days: int = 30):
        """Eski sonuçları temizle"""
        query = """
            DELETE FROM scan_results 
            WHERE created_at < DATE_SUB(NOW(), INTERVAL %s DAY)
        """
        result = self.execute_query(query, (days,))
        logging.info(f"Cleaned up old scan results: {result} rows affected")
        return result
    
    def get_domain_scan_summary(self, domain: str) -> Optional[Dict]:
        """Specific domain'in tarama özetini al"""
        query = """
            SELECT 
                d.domain,
                d.status as domain_status,
                COUNT(sr.id) as total_scans,
                AVG(sr.score) as avg_score,
                MIN(sr.risk_level) as best_risk,
                MAX(sr.risk_level) as worst_risk,
                MAX(sr.created_at) as last_scan
            FROM domains d
            LEFT JOIN scan_results sr ON d.id = sr.domain_id
            WHERE d.domain = %s
            GROUP BY d.id, d.domain, d.status
        """
        results = self.execute_query(query, (domain,), commit=False)
        return results[0] if results else None
    
    def get_module_performance_stats(self, job_id: int) -> List[Dict]:
        """Modül performans istatistikleri"""
        query = """
            SELECT 
                sr.module_name,
                COUNT(*) as total_runs,
                AVG(sr.execution_time) as avg_execution_time,
                MIN(sr.execution_time) as min_execution_time,
                MAX(sr.execution_time) as max_execution_time,
                AVG(sr.score) as avg_score,
                COUNT(CASE WHEN sr.risk_level = 'high' OR sr.risk_level = 'critical' THEN 1 END) as high_risk_count
            FROM scan_results sr
            JOIN domains d ON sr.domain_id = d.id
            WHERE d.job_id = %s
            GROUP BY sr.module_name
            ORDER BY avg_execution_time DESC
        """
        return self.execute_query(query, (job_id,), commit=False)
    
    def health_check(self) -> Dict:
        """Database health check"""
        try:
            connection = self.get_connection()
            cursor = connection.cursor()
            
            # Basic connectivity test
            cursor.execute("SELECT 1 as test")
            result = cursor.fetchone()
            
            # Pool status
            pool_size = self.pool.pool_size
            
            cursor.close()
            connection.close()
            
            return {
                "status": "healthy",
                "connection_test": result[0] == 1,
                "pool_size": pool_size,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }

# Singleton instance
db_manager = DatabaseManager()