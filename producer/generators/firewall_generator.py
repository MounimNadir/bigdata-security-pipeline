import random
from datetime import datetime
from faker import Faker

from utils.ip_pool import (
    get_source_ip, get_internal_server_ip,
    get_employee_ip, get_country
)

fake = Faker()

# ============================================================
# Common ports and their protocols
# ============================================================
COMMON_PORTS = {
    22:    "TCP",   # SSH
    80:    "TCP",   # HTTP
    443:   "TCP",   # HTTPS
    3306:  "TCP",   # MySQL
    5432:  "TCP",   # PostgreSQL
    6379:  "TCP",   # Redis
    27017: "TCP",   # MongoDB
    8080:  "TCP",   # HTTP alternate
    8443:  "TCP",   # HTTPS alternate
    21:    "TCP",   # FTP
    25:    "TCP",   # SMTP
    53:    "UDP",   # DNS
    123:   "UDP",   # NTP
}

# Ports that should NEVER receive external traffic
# Connections to these are always suspicious
SUSPICIOUS_PORTS = [23, 445, 1433, 3389, 4444, 5900, 6666, 31337]

PROTOCOLS = ["TCP", "UDP", "ICMP"]


def _mac_address() -> str:
    """Generate a realistic MAC address."""
    return fake.mac_address().upper()


def _timestamp() -> str:
    return datetime.now().strftime("%b %d %H:%M:%S")


def generate_blocked_connection(src_ip: str = None,
                                dst_port: int = None) -> dict:
    """
    Generate a UFW BLOCK event.

    Real log format:
    Jun 13 03:42:11 firewall01 kernel: [UFW BLOCK] IN=eth0 OUT=
    MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:08:00
    SRC=185.220.101.45 DST=10.0.0.1
    LEN=60 TOS=0x00 PREC=0x00 TTL=49 ID=12345
    PROTO=TCP SPT=54832 DPT=22 WINDOW=1024 RES=0x00 SYN URGP=0
    """
    ip = src_ip or get_source_ip(malicious=False)
    dst_ip = get_internal_server_ip()
    port = dst_port or random.choice(list(COMMON_PORTS.keys()))
    protocol = COMMON_PORTS.get(port, "TCP")
    src_port = random.randint(49152, 65535)
    ts = _timestamp()

    raw = (
        f"{ts} firewall01 kernel: [UFW BLOCK] "
        f"IN=eth0 OUT= MAC={_mac_address()} "
        f"SRC={ip} DST={dst_ip} "
        f"LEN=60 PROTO={protocol} "
        f"SPT={src_port} DPT={port}"
    )

    return {
        "raw": raw,
        "timestamp": datetime.now().isoformat(),
        "source_ip": ip,
        "destination_ip": dst_ip,
        "source_port": src_port,
        "destination_port": port,
        "username": None,
        "action": "block",
        "protocol": protocol,
        "bytes_sent": random.randint(40, 1500),
        "country": get_country(ip),
        "topic": "firewall",
    }


def generate_allowed_connection(src_ip: str = None) -> dict:
    """
    Generate a UFW ALLOW event (normal traffic passing through).
    """
    ip = src_ip or get_source_ip(malicious=False)
    dst_ip = get_internal_server_ip()
    port = random.choice([80, 443, 22, 8080])
    protocol = COMMON_PORTS.get(port, "TCP")
    src_port = random.randint(49152, 65535)
    bytes_sent = random.randint(200, 50000)
    ts = _timestamp()

    raw = (
        f"{ts} firewall01 kernel: [UFW ALLOW] "
        f"IN=eth0 OUT= MAC={_mac_address()} "
        f"SRC={ip} DST={dst_ip} "
        f"LEN={bytes_sent} PROTO={protocol} "
        f"SPT={src_port} DPT={port}"
    )

    return {
        "raw": raw,
        "timestamp": datetime.now().isoformat(),
        "source_ip": ip,
        "destination_ip": dst_ip,
        "source_port": src_port,
        "destination_port": port,
        "username": None,
        "action": "allow",
        "protocol": protocol,
        "bytes_sent": bytes_sent,
        "country": get_country(ip),
        "topic": "firewall",
    }


def generate_suspicious_port_connection(src_ip: str = None) -> dict:
    """
    Generate a connection attempt to a suspicious port.
    These should occasionally appear in normal traffic
    to create background noise for the detector.
    """
    ip = src_ip or get_source_ip(malicious=True)
    dst_ip = get_internal_server_ip()
    port = random.choice(SUSPICIOUS_PORTS)
    src_port = random.randint(49152, 65535)
    ts = _timestamp()

    raw = (
        f"{ts} firewall01 kernel: [UFW BLOCK] "
        f"IN=eth0 OUT= MAC={_mac_address()} "
        f"SRC={ip} DST={dst_ip} "
        f"LEN=60 PROTO=TCP "
        f"SPT={src_port} DPT={port}"
    )

    return {
        "raw": raw,
        "timestamp": datetime.now().isoformat(),
        "source_ip": ip,
        "destination_ip": dst_ip,
        "source_port": src_port,
        "destination_port": port,
        "username": None,
        "action": "block_suspicious_port",
        "protocol": "TCP",
        "bytes_sent": random.randint(40, 100),
        "country": get_country(ip),
        "topic": "firewall",
    }


def generate_normal_event() -> dict:
    """
    Generate a random normal firewall event.
    Weighted: mostly allowed, some blocked, rare suspicious port.
    """
    roll = random.random()
    if roll < 0.65:
        return generate_allowed_connection()
    elif roll < 0.90:
        return generate_blocked_connection()
    else:
        return generate_suspicious_port_connection()