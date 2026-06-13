import time
import random
from datetime import datetime
from utils.ip_pool import get_malicious_ip, get_country
from generators.web_generator import SCANNER_URLS, SCANNER_AGENTS

# ============================================================
# Web Application Scanner Scenario
#
# What this simulates:
# An attacker runs tools like Nikto, DirBuster, or WPScan
# to find vulnerable files, admin panels, and configuration
# files exposed on a web server.
#
# What Spark should detect:
# Same IP requesting > 20 distinct URLs in 1 minute
# with > 50% returning 404/403 → MED/HIGH
# ============================================================

# Extended list of paths scanners probe
EXTENDED_SCANNER_PATHS = SCANNER_URLS + [
    "/backup.sql", "/dump.sql", "/database.sql",
    "/wp-content/uploads/", "/xmlrpc.php",
    "/.htaccess", "/.htpasswd", "/web.config",
    "/app/config/parameters.yml",
    "/config/database.yml",
    "/storage/logs/laravel.log",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/api/v1/../../etc/passwd",
    "/cgi-bin/test.cgi", "/cgi-bin/printenv.pl",
]


def run(kafka_producer, topic: str, src_ip: str = None) -> dict:
    """
    Execute a web application scanning scenario.

    Simulates an automated scanner probing for
    vulnerable endpoints, exposed files, and
    common CMS vulnerabilities.
    """
    attacker_ip = src_ip or get_malicious_ip()
    agent = random.choice(SCANNER_AGENTS)

    # Scanners probe 30-80 paths
    num_paths = random.randint(30, 80)
    paths = random.choices(EXTENDED_SCANNER_PATHS, k=num_paths)

    # Automated scanners are fast but not as fast as nmap
    delay = 0.08

    print(f"[ATTACK] Web scan: {attacker_ip} → {num_paths} paths")

    sent = 0
    error_count = 0

    for path in paths:
        # Most scanner requests get 404 or 403
        status = random.choices(
            [404, 403, 200, 500],
            weights=[0.50, 0.30, 0.10, 0.10]
        )[0]

        if status in [404, 403]:
            error_count += 1

        size = random.randint(100, 500)
        ts = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")

        raw = (
            f'{attacker_ip} - - [{ts}] '
            f'"GET {path} HTTP/1.1" '
            f'{status} {size} '
            f'"-" "{agent}"'
        )

        event = {
            "raw": raw,
            "timestamp": datetime.now().isoformat(),
            "source_ip": attacker_ip,
            "destination_ip": "10.0.0.10",
            "source_port": random.randint(49152, 65535),
            "destination_port": 80,
            "username": None,
            "action": f"http_{status}",
            "protocol": "TCP",
            "bytes_sent": size,
            "country": get_country(attacker_ip),
            "topic": "web",
            "url": path,
            "http_method": "GET",
            "http_status": status,
        }

        kafka_producer.send(topic, value=event)
        sent += 1
        time.sleep(delay)

    kafka_producer.flush()

    return {
        "type": "web_scan",
        "attacker_ip": attacker_ip,
        "paths_probed": sent,
        "errors": error_count,
        "error_rate": round(error_count / sent, 2),
    }