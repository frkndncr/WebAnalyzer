"""Sensitive files and consoles left on a web server (.git, .env, backups, phpinfo, actuator ...).

ACTIVE: it requests about 25 well-known paths on the target, so on the public demo it
only runs for domains whose owner has verified them. Each hit is confirmed by what the
file contains, not just a 200 status, so a catch-all page does not produce findings.
"""
import re
import time

from modules.registry import module
from utils import webprobe

READ_BYTES = 4096
PAUSE = 0.15          # seconds between requests: this is a check, not a load test


def _contains(*needles):
    return lambda text, raw: any(n in text for n in needles)


def _regex(pattern, flags=0):
    compiled = re.compile(pattern, flags)
    return lambda text, raw: bool(compiled.search(text))


def _magic(prefix):
    return lambda text, raw: raw.startswith(prefix)


def _not_html(check):
    return lambda text, raw: not text.lstrip().lower().startswith(("<!doctype", "<html")) and check(text, raw)


# path, title, severity, validator, recommendation
CHECKS = [
    ("/.git/HEAD", "Git repository exposed", "high", _regex(r"^ref:\s*refs/", re.M), "Block access to /.git and remove it from the web root."),
    ("/.git/config", "Git configuration exposed", "high", _contains("[core]"), "Block access to /.git and remove it from the web root."),
    ("/.env", "Environment file exposed", "critical", _not_html(_regex(r"^[A-Z][A-Z0-9_]{2,}\s*=", re.M)), "Remove .env from the web root and rotate every secret it contains."),
    ("/.htpasswd", "Password file exposed", "high", _regex(r"^[^:\s]+:(\$|\{SHA\}|[A-Za-z0-9./]{13})", re.M), "Move .htpasswd outside the web root and change the passwords."),
    ("/.DS_Store", "macOS .DS_Store exposed", "low", _magic(b"\x00\x00\x00\x01Bud1"), "Delete .DS_Store files from the web root."),
    ("/.vscode/sftp.json", "Editor deployment config exposed", "high", _contains('"host"', '"password"'), "Remove editor configuration from the web root and rotate the credentials."),
    ("/backup.zip", "Backup archive exposed", "high", _magic(b"PK\x03\x04"), "Remove backups from the web root."),
    ("/backup.sql", "Database dump exposed", "critical", _regex(r"CREATE TABLE|INSERT INTO|DROP TABLE", re.I), "Remove database dumps from the web root and rotate credentials."),
    ("/dump.sql", "Database dump exposed", "critical", _regex(r"CREATE TABLE|INSERT INTO|DROP TABLE", re.I), "Remove database dumps from the web root and rotate credentials."),
    ("/db.sql", "Database dump exposed", "critical", _regex(r"CREATE TABLE|INSERT INTO|DROP TABLE", re.I), "Remove database dumps from the web root and rotate credentials."),
    ("/wp-config.php.bak", "WordPress configuration backup exposed", "critical", _contains("DB_PASSWORD", "DB_NAME"), "Delete the backup and rotate the database credentials."),
    ("/config.php.bak", "Configuration backup exposed", "high", _regex(r"password|secret|DB_", re.I), "Delete the backup and rotate the credentials."),
    ("/phpinfo.php", "phpinfo() page exposed", "medium", _contains("PHP Version", "phpinfo()"), "Remove phpinfo files from production."),
    ("/info.php", "phpinfo() page exposed", "medium", _contains("PHP Version", "phpinfo()"), "Remove phpinfo files from production."),
    ("/server-status", "Apache server-status exposed", "medium", _contains("Apache Server Status"), "Restrict /server-status to localhost."),
    ("/server-info", "Apache server-info exposed", "medium", _contains("Apache Server Information"), "Restrict /server-info to localhost."),
    ("/actuator/env", "Spring Boot actuator /env exposed", "high", _contains("propertySources"), "Restrict actuator endpoints or require authentication."),
    ("/actuator/heapdump", "Spring Boot heap dump exposed", "critical", lambda text, raw: raw.startswith(b"JAVA PROFILE"), "Disable the heapdump endpoint."),
    ("/actuator", "Spring Boot actuator exposed", "low", _contains('"_links"'), "Restrict actuator endpoints or require authentication."),
    ("/console", "Debug console exposed", "high", _contains("Werkzeug", "Interactive Console"), "Never expose a debug console in production."),
    ("/swagger.json", "API specification exposed", "low", _contains('"swagger"', '"openapi"'), "Restrict API documentation if the API is not public."),
    ("/openapi.json", "API specification exposed", "low", _contains('"openapi"'), "Restrict API documentation if the API is not public."),
    ("/swagger-ui.html", "Swagger UI exposed", "low", _contains("swagger-ui", "Swagger UI"), "Restrict API documentation if the API is not public."),
    ("/api-docs", "API documentation exposed", "low", _contains('"swagger"', '"openapi"'), "Restrict API documentation if the API is not public."),
]


def check_path(domain, path, validator, get, sleep):
    sleep(PAUSE)
    response, url = webprobe.fetch(domain, path, get=get, max_redirects=0)
    if response is None or response.status_code != 200:
        return None
    raw = webprobe.body(response, READ_BYTES)
    text = raw.decode("utf-8", "replace")
    return url if validator(text, raw) else None


@module("Exposed Files", description="Sensitive files and consoles left on the web server", group="security", weight="medium", active=True, order=180)
def exposed_files(domain, get=None, sleep=time.sleep):
    domain = webprobe.clean_host(domain)
    if not domain:
        return {"error": "not a valid domain name"}
    findings = []
    for path, title, severity, validator, recommendation in CHECKS:
        url = check_path(domain, path, validator, get, sleep)
        if url:
            findings.append({"title": title, "severity": severity, "location": url,
                             "description": f"{path} is publicly readable and its content matches what that file normally contains.",
                             "recommendation": recommendation})
    return {"paths_checked": len(CHECKS), "findings": findings}
