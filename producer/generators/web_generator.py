import random
from datetime import datetime
from faker import Faker

from utils.ip_pool import get_source_ip, get_country

fake = Faker()

# ============================================================
# Realistic URL pools
# ============================================================
NORMAL_URLS = [
    "/", "/index.html", "/about", "/contact",
    "/api/v1/users", "/api/v1/products", "/api/v1/orders",
    "/static/css/main.css", "/static/js/app.js",
    "/favicon.ico", "/robots.txt", "/sitemap.xml",
    "/login", "/logout", "/dashboard", "/profile",
]

# URLs that scanners probe looking for vulnerabilities
SCANNER_URLS = [
    "/wp-admin", "/wp-login.php", "/wp-config.php",
    "/.env", "/.git/config", "/config.php",
    "/phpmyadmin", "/pma", "/admin", "/administrator",
    "/shell.php", "/cmd.php", "/backdoor.php",
    "/etc/passwd", "/../../../etc/passwd",
    "/api/swagger.json", "/api/v1/admin",
    "/.aws/credentials", "/server-status",
]

# Realistic HTTP methods distribution
HTTP_METHODS = {
    "GET": 0.75,
    "POST": 0.15,
    "PUT": 0.05,
    "DELETE": 0.03,
    "OPTIONS": 0.02,
}

# Status codes and their realistic weights
NORMAL_STATUS = {200: 0.70, 301: 0.10, 304: 0.10, 404: 0.08, 403: 0.02}
SCANNER_STATUS = {404: 0.50, 403: 0.30, 200: 0.10, 500: 0.10}

# Realistic user agents
NORMAL_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
]

SCANNER_AGENTS = [
    "Mozilla/5.0 (compatible; Googlebot/2.1)",
    "Nikto/2.1.6",
    "sqlmap/1.7",
    "WPScan v3.8",
    "python-requests/2.28.0",
    "-",
]


def _weighted_choice(choices: dict):
    """Pick a key from a dict where values are weights."""
    keys = list(choices.keys())
    weights = list(choices.values())
    return random.choices(keys, weights=weights, k=1)[0]


def _timestamp() -> str:
    return datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")


def generate_normal_request(src_ip: str = None) -> dict:
    """
    Generate a normal web request.

    Real Apache combined log format:
    185.220.101.45 - - [13/Jun/2026:03:42:11 +0000]
    "GET /index.html HTTP/1.1" 200 1234
    "https://example.com" "Mozilla/5.0..."
    """
    ip = src_ip or get_source_ip(malicious=False)
    method = _weighted_choice(HTTP_METHODS)
    url = random.choice(NORMAL_URLS)
    status = _weighted_choice(NORMAL_STATUS)
    size = random.randint(200, 50000)
    agent = random.choice(NORMAL_AGENTS)
    referer = random.choice(["-", "https://google.com", "https://example.com"])
    ts = _timestamp()

    raw = (
        f'{ip} - - [{ts}] '
        f'"{method} {url} HTTP/1.1" '
        f'{status} {size} '
        f'"{referer}" "{agent}"'
    )

    return {
        "raw": raw,
        "timestamp": datetime.now().isoformat(),
        "source_ip": ip,
        "destination_ip": "10.0.0.10",
        "source_port": random.randint(49152, 65535),
        "destination_port": 80,
        "username": None,
        "action": f"http_{status}",
        "protocol": "TCP",
        "bytes_sent": size,
        "country": get_country(ip),
        "topic": "web",
        "url": url,
        "http_method": method,
        "http_status": status,
    }


def generate_scanner_request(src_ip: str = None) -> dict:
    """
    Generate a web scanner probe request.
    These are the kind of requests tools like Nikto and DirBuster make.
    """
    ip = src_ip or get_source_ip(malicious=True)
    method = "GET"
    url = random.choice(SCANNER_URLS)
    status = _weighted_choice(SCANNER_STATUS)
    size = random.randint(100, 500)
    agent = random.choice(SCANNER_AGENTS)
    ts = _timestamp()

    raw = (
        f'{ip} - - [{ts}] '
        f'"{method} {url} HTTP/1.1" '
        f'{status} {size} '
        f'"-" "{agent}"'
    )

    return {
        "raw": raw,
        "timestamp": datetime.now().isoformat(),
        "source_ip": ip,
        "destination_ip": "10.0.0.10",
        "source_port": random.randint(49152, 65535),
        "destination_port": 80,
        "username": None,
        "action": f"http_{status}",
        "protocol": "TCP",
        "bytes_sent": size,
        "country": get_country(ip),
        "topic": "web",
        "url": url,
        "http_method": method,
        "http_status": status,
    }


def generate_normal_event() -> dict:
    """
    Generate a random web event.
    Weighted: mostly normal requests, occasional scanner probe.
    """
    if random.random() < 0.92:
        return generate_normal_request()
    return generate_scanner_request()