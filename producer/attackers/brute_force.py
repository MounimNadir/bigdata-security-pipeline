import time
import random
from generators.auth_generator import generate_login_fail, generate_login_success

# ============================================================
# SSH Brute Force Attack Scenario
#
# What this simulates:
# An attacker runs a tool like Hydra or Medusa that rapidly
# tries hundreds of username/password combinations against SSH.
# This is the most common attack on any internet-facing server.
#
# What Spark should detect:
# > 10 login_fail events from same IP within 1 minute → HIGH
# Followed by login_success from same IP → CRIT
# ============================================================

# Usernames attackers typically try in order
BRUTE_FORCE_USERNAMES = [
    "root", "admin", "administrator", "ubuntu",
    "ec2-user", "pi", "deploy", "git", "oracle",
    "postgres", "test", "guest", "user", "mysql",
]


def run(kafka_producer, topic: str, src_ip: str = None) -> dict:
    """
    Execute a brute force attack scenario.

    Sends a rapid burst of failed logins from one IP,
    then optionally a successful login to simulate
    the attacker finding valid credentials.

    Returns metadata about the attack for logging.
    """
    from utils.ip_pool import get_malicious_ip
    attacker_ip = src_ip or get_malicious_ip()

    # How many attempts this attack makes
    num_attempts = random.randint(20, 50)

    # How fast between attempts (seconds)
    # Real tools like Hydra send ~10 attempts/second
    delay = 0.1

    print(f"[ATTACK] Brute force starting: {attacker_ip} → {num_attempts} attempts")

    sent = 0
    for i in range(num_attempts):
        username = BRUTE_FORCE_USERNAMES[i % len(BRUTE_FORCE_USERNAMES)]
        event = generate_login_fail(src_ip=attacker_ip)
        event["username"] = username

        kafka_producer.send(topic, value=event)
        sent += 1
        time.sleep(delay)

    # 30% chance the attacker succeeds after the brute force
    success = False
    if random.random() < 0.30:
        success_event = generate_login_success(src_ip=attacker_ip)
        success_event["username"] = "root"
        kafka_producer.send(topic, value=success_event)
        success = True
        print(f"[ATTACK] Brute force SUCCESS: {attacker_ip} logged in as root")

    kafka_producer.flush()

    return {
        "type": "brute_force",
        "attacker_ip": attacker_ip,
        "attempts": sent,
        "success": success,
    }