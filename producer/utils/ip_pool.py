import random
import ipaddress

# ============================================================
# Known malicious IP ranges (real Tor exit node / scanner ranges)
# Used for blacklist detection rule
# ============================================================
MALICIOUS_RANGES = [
    "185.220.101.0/24",   # Tor exit nodes
    "185.220.100.0/24",   # Tor exit nodes
    "45.33.32.0/24",      # Known scanner (Shodan)
    "80.82.77.0/24",      # Known scanner
    "89.248.167.0/24",    # Known scanner
    "209.141.36.0/24",    # Tor exit nodes
]

# ============================================================
# Normal external IP ranges (legitimate internet traffic)
# ============================================================
NORMAL_EXTERNAL_RANGES = [
    "8.8.0.0/16",         # Google
    "1.1.1.0/24",         # Cloudflare
    "93.184.0.0/16",      # Example.com / Akamai
    "151.101.0.0/16",     # Fastly CDN
    "13.32.0.0/15",       # Amazon CloudFront
]

# ============================================================
# Internal network ranges
# ============================================================
INTERNAL_SERVER_RANGE = "10.0.0.0/24"      # servers
EMPLOYEE_RANGE        = "192.168.1.0/24"   # workstations

# ============================================================
# Country mapping per IP range (replaces GeoIP database)
# ============================================================
IP_COUNTRY_MAP = {
    "185.220.101": "DE",   # Germany (Tor)
    "185.220.100": "NL",   # Netherlands (Tor)
    "45.33.32":    "US",   # United States (Shodan)
    "80.82.77":    "NL",   # Netherlands
    "89.248.167":  "NL",   # Netherlands
    "209.141.36":  "US",   # United States
    "8.8":         "US",   # Google US
    "1.1.1":       "AU",   # Cloudflare Australia
    "93.184":      "US",   # Akamai US
    "151.101":     "US",   # Fastly US
    "13.32":       "US",   # Amazon US
    "10.0.0":      "INT",  # Internal
    "192.168.1":   "INT",  # Internal
}


def _random_ip_from_range(cidr: str) -> str:
    """Pick a random IP address from a CIDR range."""
    network = ipaddress.IPv4Network(cidr, strict=False)
    # Convert to list of hosts and pick one randomly
    # For large ranges we calculate directly to avoid memory issues
    network_int = int(network.network_address)
    broadcast_int = int(network.broadcast_address)
    random_int = random.randint(network_int + 1, broadcast_int - 1)
    return str(ipaddress.IPv4Address(random_int))


def get_malicious_ip() -> str:
    """Return a random IP from known malicious ranges."""
    cidr = random.choice(MALICIOUS_RANGES)
    return _random_ip_from_range(cidr)


def get_normal_external_ip() -> str:
    """Return a random IP from normal external ranges."""
    cidr = random.choice(NORMAL_EXTERNAL_RANGES)
    return _random_ip_from_range(cidr)


def get_internal_server_ip() -> str:
    """Return a random internal server IP."""
    return _random_ip_from_range(INTERNAL_SERVER_RANGE)


def get_employee_ip() -> str:
    """Return a random employee workstation IP."""
    return _random_ip_from_range(EMPLOYEE_RANGE)


def get_source_ip(malicious: bool = False) -> str:
    """
    Return a source IP address.
    During normal traffic: 90% normal external, 10% malicious.
    During attack: always malicious.
    """
    if malicious:
        return get_malicious_ip()
    # 10% chance of malicious IP even in normal traffic
    # This simulates background noise of internet scanners
    if random.random() < 0.10:
        return get_malicious_ip()
    return get_normal_external_ip()


def get_country(ip: str) -> str:
    """
    Return country code for an IP address.
    Uses prefix matching against our IP_COUNTRY_MAP.
    """
    # Try matching on first three octets
    prefix3 = ".".join(ip.split(".")[:3])
    if prefix3 in IP_COUNTRY_MAP:
        return IP_COUNTRY_MAP[prefix3]

    # Try matching on first two octets
    prefix2 = ".".join(ip.split(".")[:2])
    if prefix2 in IP_COUNTRY_MAP:
        return IP_COUNTRY_MAP[prefix2]

    return "UNKNOWN"


def is_blacklisted(ip: str) -> bool:
    """
    Check if an IP belongs to a known malicious range.
    Used by Spark's blacklist detection rule.
    """
    try:
        ip_obj = ipaddress.IPv4Address(ip)
        for cidr in MALICIOUS_RANGES:
            if ip_obj in ipaddress.IPv4Network(cidr, strict=False):
                return True
    except ValueError:
        pass
    return False


# ============================================================
# Export the full blacklist as a list of CIDR strings
# Used by Spark to broadcast the blacklist to all workers
# ============================================================
BLACKLIST_CIDRS = MALICIOUS_RANGES.copy()