-- Ana tarama işleri tablosu
CREATE TABLE IF NOT EXISTS scan_jobs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    job_name VARCHAR(255),
    total_domains INT DEFAULT 0,
    completed_domains INT DEFAULT 0,
    status ENUM('pending', 'running', 'completed', 'failed') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP NULL,
    completed_at TIMESTAMP NULL,
    INDEX idx_status (status),
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Domain listesi
CREATE TABLE IF NOT EXISTS domains (
    id INT AUTO_INCREMENT PRIMARY KEY,
    job_id INT,
    domain VARCHAR(255) NOT NULL,
    status ENUM('pending', 'scanning', 'completed', 'failed') DEFAULT 'pending',
    priority INT DEFAULT 5,
    retry_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    scanned_at TIMESTAMP NULL,
    FOREIGN KEY (job_id) REFERENCES scan_jobs(id) ON DELETE CASCADE,
    UNIQUE KEY unique_job_domain (job_id, domain),
    INDEX idx_status (status),
    INDEX idx_priority (priority)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Tarama sonuçları
CREATE TABLE IF NOT EXISTS scan_results (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain_id INT,
    module_name VARCHAR(100),
    status VARCHAR(50),
    risk_level ENUM('low', 'medium', 'high', 'critical'),
    score INT,
    execution_time FLOAT,
    result_data JSON,
    error_message TEXT,
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
    INDEX idx_domain (domain_id),
    INDEX idx_module (module_name),
    INDEX idx_risk (risk_level)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Bulunan zafiyetler
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain_id INT,
    vulnerability_type VARCHAR(100),
    severity ENUM('info', 'low', 'medium', 'high', 'critical'),
    module_name VARCHAR(100),
    details JSON,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
    INDEX idx_severity (severity),
    INDEX idx_type (vulnerability_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Teknoloji tespitleri
CREATE TABLE IF NOT EXISTS technologies (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain_id INT,
    category VARCHAR(100),
    name VARCHAR(255),
    version VARCHAR(50),
    confidence INT,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
    INDEX idx_domain (domain_id),
    INDEX idx_category (category)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- İstatistikler
CREATE TABLE IF NOT EXISTS statistics (
    id INT AUTO_INCREMENT PRIMARY KEY,
    job_id INT,
    total_scanned INT DEFAULT 0,
    total_vulnerabilities INT DEFAULT 0,
    avg_scan_time FLOAT,
    success_rate FLOAT,
    risk_distribution JSON,
    technology_distribution JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (job_id) REFERENCES scan_jobs(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Loglar
CREATE TABLE IF NOT EXISTS scan_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain_id INT,
    log_level ENUM('debug', 'info', 'warning', 'error', 'critical'),
    message TEXT,
    module_name VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
    INDEX idx_level (log_level),
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;