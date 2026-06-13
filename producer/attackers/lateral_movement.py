import time
import random
from datetime import datetime
from utils.ip_pool import get_internal_server_ip, get_country

# ============================================================
# Lateral Movement Scenario
#
# What this simulates:
# After breaching one internal machine, an attacker
# tries to spread to other internal machines by
# attempting SSH or SMB connections to neighboring hosts.
# This is a classic post-exploitation technique.
#
# What Spark should detect:
# Same internal IP connecting to > 5 distinct internal
# destination IPs within 2 minutes → CRIT
# ============================================================

# Ports used for lateral movement
LATERAL_PORTS = [
    22,    # SSH
    445,   # SMB (Windows file sharing)
    3389,  # RDP (Remote Desktop)
    5985,  # WinRM HTTP
    5986,  # WinRM HTTPS
]


def run(kafka_producer,
        auth_topic: str,
        firewall_topic: str,
        src_ip: str = None) -> dict:
    """
    Execute a lateral movement scenario.

    Simulates an attacker on a compromised internal machine
    scanning and attempting to connect to other internal hosts.

    Uses both auth and firewall topics because lateral
    movement generates both SSH attempts and firewall events.
    """
    # The already-compromised internal machine
    compromised_ip = src_ip or get_internal_server_ip()

    # Number of internal hosts to probe
    num_targets = random.randint(6, 15)

    # Generate distinct target IPs
    targets = set()
    while len(targets) < num_targets:
        ip = get_internal_server_ip()
        if ip != compromised_ip:
            targets.add(ip)
    targets = list(targets)

    print(
        f"[ATTACK] Lateral movement: {compromised_ip} "
        f"→ {num_targets} internal targets"
    )

    sent_auth = 0
    sent_firewall = 0

    for target_ip in targets:
        port = random.choice(LATERAL_PORTS)
        ts = datetime.now().strftime("%b %d %H:%M:%S")

        # Generate firewall event (connection attempt)
        firewall_event = {
            "raw": (
                f"{ts} firewall01 kernel: [UFW BLOCK] "
                f"IN=eth1 OUT= "
                f"SRC={compromised_ip} DST={target_ip} "
                f"PROTO=TCP "
                f"SPT={random.randint(49152, 65535)} DPT={port}"
            ),
            "timestamp": datetime.now().isoformat(),
            "source_ip": compromised_ip,
            "destination_ip": target_ip,
            "source_port": random.randint(49152, 65535),
            "destination_port": port,
            "username": None,
            "action": "block",
            "protocol": "TCP",
            "bytes_sent": 60,
            "country": "INT",
            "topic": "firewall",
        }
        kafka_producer.send(firewall_topic, value=firewall_event)
        sent_firewall += 1

        # If SSH port, also generate auth event
        if port == 22:
            from generators.auth_generator import (
                generate_login_fail,
                COMMON_TARGETS
            )
            auth_event = generate_login_fail(src_ip=compromised_ip)
            auth_event["destination_ip"] = target_ip
            kafka_producer.send(auth_topic, value=auth_event)
            sent_auth += 1

        # Lateral movement is slower than external scans
        # Attacker is being careful to avoid detection
        time.sleep(random.uniform(0.5, 2.0))

    kafka_producer.flush()

    return {
        "type": "lateral_movement",
        "compromised_ip": compromised_ip,
        "targets_probed": len(targets),
        "firewall_events": sent_firewall,
        "auth_events": sent_auth,
    }