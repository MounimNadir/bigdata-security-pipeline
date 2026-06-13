import time
import random
from datetime import datetime
from utils.ip_pool import get_malicious_ip, get_internal_server_ip, get_country

# ============================================================
# Port Scan Attack Scenario
#
# What this simulates:
# An attacker runs nmap to discover which ports are open
# on your servers. This is always the first step before
# a targeted attack — reconnaissance.
#
# What Spark should detect:
# Same IP connecting to > 10 distinct ports in 1 minute → HIGH
# ============================================================

# Nmap default port scan order (most common ports first)
NMAP_TOP_PORTS = [
    22, 80, 443, 21, 25, 53, 110, 143, 445, 3389,
    8080, 8443, 3306, 5432, 6379, 27017, 1433, 5900,
    23, 111, 135, 139, 389, 636, 1521, 2049, 2181,
    4444, 5000, 5001, 6666, 7001, 8888, 9200, 9300,
]


def run(kafka_producer, topic: str, src_ip: str = None) -> dict:
    """
    Execute a port scan scenario.

    Simulates nmap scanning a target host by rapidly
    attempting connections to many different ports.
    Most are blocked (RST or timeout), which generates
    UFW BLOCK log entries.
    """
    attacker_ip = src_ip or get_malicious_ip()
    target_ip = get_internal_server_ip()

    # Scan between 15 and 35 ports
    num_ports = random.randint(15, 35)
    ports_to_scan = random.sample(NMAP_TOP_PORTS, min(num_ports, len(NMAP_TOP_PORTS)))

    # Nmap SYN scan is very fast — ~100-1000 ports/second
    delay = 0.05

    print(f"[ATTACK] Port scan: {attacker_ip} → {target_ip} ({num_ports} ports)")

    sent = 0
    for port in ports_to_scan:
        event = {
            "raw": (
                f"{datetime.now().strftime('%b %d %H:%M:%S')} "
                f"firewall01 kernel: [UFW BLOCK] "
                f"IN=eth0 OUT= SRC={attacker_ip} DST={target_ip} "
                f"PROTO=TCP SPT={random.randint(49152, 65535)} DPT={port}"
            ),
            "timestamp": datetime.now().isoformat(),
            "source_ip": attacker_ip,
            "destination_ip": target_ip,
            "source_port": random.randint(49152, 65535),
            "destination_port": port,
            "username": None,
            "action": "block",
            "protocol": "TCP",
            "bytes_sent": 60,
            "country": get_country(attacker_ip),
            "topic": "firewall",
        }

        kafka_producer.send(topic, value=event)
        sent += 1
        time.sleep(delay)

    kafka_producer.flush()

    return {
        "type": "port_scan",
        "attacker_ip": attacker_ip,
        "target_ip": target_ip,
        "ports_scanned": sent,
    }