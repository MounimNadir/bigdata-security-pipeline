import time
import random
from datetime import datetime
from utils.ip_pool import get_malicious_ip, get_internal_server_ip, get_country

# ============================================================
# Data Exfiltration Scenario
#
# What this simulates:
# After a successful breach, an attacker copies large amounts
# of sensitive data (databases, files) out of the network.
# This is characterized by unusually large outbound transfers.
#
# What Spark should detect:
# bytes_sent > 100MB from same internal IP
# within a 5-minute window → CRIT
# ============================================================

# Size of each exfiltration "chunk" in bytes
# Real exfiltration often splits data into chunks
# to avoid triggering simple size-based alerts
CHUNK_SIZE_MIN = 5_000_000    #  5 MB per chunk
CHUNK_SIZE_MAX = 20_000_000   # 20 MB per chunk


def run(kafka_producer, topic: str, src_ip: str = None) -> dict:
    """
    Execute a data exfiltration scenario.

    Simulates an attacker who has already compromised
    an internal machine and is transferring large volumes
    of data to an external server.

    Uses an internal source IP because the exfiltration
    originates from inside the network after compromise.
    """
    # Exfiltration comes FROM an internal compromised machine
    compromised_ip = get_internal_server_ip()
    # Going TO an external attacker-controlled server
    attacker_ip = src_ip or get_malicious_ip()

    # Total data to exfiltrate: 200MB to 1GB
    total_bytes = random.randint(200_000_000, 1_000_000_000)
    bytes_remaining = total_bytes
    chunks_sent = 0
    total_sent = 0

    print(
        f"[ATTACK] Exfiltration: {compromised_ip} → {attacker_ip} "
        f"({total_bytes / 1_000_000:.0f} MB)"
    )

    while bytes_remaining > 0:
        chunk_size = min(
            random.randint(CHUNK_SIZE_MIN, CHUNK_SIZE_MAX),
            bytes_remaining
        )

        ts = datetime.now().strftime("%b %d %H:%M:%S")
        raw = (
            f"{ts} firewall01 kernel: [UFW ALLOW] "
            f"IN= OUT=eth0 "
            f"SRC={compromised_ip} DST={attacker_ip} "
            f"LEN={chunk_size} PROTO=TCP "
            f"SPT={random.randint(49152, 65535)} DPT=443"
        )

        event = {
            "raw": raw,
            "timestamp": datetime.now().isoformat(),
            "source_ip": compromised_ip,
            "destination_ip": attacker_ip,
            "source_port": random.randint(49152, 65535),
            "destination_port": 443,
            "username": None,
            "action": "allow",
            "protocol": "TCP",
            "bytes_sent": chunk_size,
            "country": get_country(compromised_ip),
            "topic": "firewall",
        }

        kafka_producer.send(topic, value=event)
        chunks_sent += 1
        total_sent += chunk_size
        bytes_remaining -= chunk_size

        # Chunks sent with small delay
        # Fast enough to stay within 5-minute window
        time.sleep(0.5)

    kafka_producer.flush()

    return {
        "type": "exfiltration",
        "compromised_ip": compromised_ip,
        "attacker_ip": attacker_ip,
        "total_bytes": total_sent,
        "chunks": chunks_sent,
    }