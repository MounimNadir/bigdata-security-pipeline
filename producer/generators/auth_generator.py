import random
import time
from datetime import datetime
from faker import Faker

from utils.ip_pool import get_source_ip, get_employee_ip, get_country

fake = Faker()

# ============================================================
# Realistic username pools
# These are the accounts attackers actually target
# ============================================================
COMMON_TARGETS = [
    "root", "admin", "administrator", "ubuntu", "ec2-user",
    "pi", "oracle", "postgres", "mysql", "deploy", "git",
    "ansible", "jenkins", "docker", "test", "guest",
]

LEGITIMATE_USERS = [
    "alice", "bob", "charlie", "diana", "eve",
    "frank", "grace", "henry", "isabel", "james",
]

# SSH port is almost always 22
SSH_PORT = 22

# Realistic sshd process ID range
PID_RANGE = (10000, 65000)


def _timestamp() -> str:
    """Generate current timestamp in syslog format."""
    return datetime.now().strftime("%b %d %H:%M:%S")


def _hostname() -> str:
    """Return a realistic server hostname."""
    return random.choice([
        "webserver01", "webserver02", "appserver01",
        "db-primary", "db-replica", "bastion-host",
        "mail-server", "vpn-gateway",
    ])


def generate_login_fail(src_ip: str = None) -> dict:
    """
    Generate a failed SSH login attempt.

    Real log format:
    Jun 13 03:42:11 webserver01 sshd[12493]: Failed password for root
    from 185.220.101.45 port 54832 ssh2
    """
    ip = src_ip or get_source_ip(malicious=False)
    username = random.choice(COMMON_TARGETS)
    hostname = _hostname()
    pid = random.randint(*PID_RANGE)
    src_port = random.randint(49152, 65535)
    ts = _timestamp()

    raw = (
        f"{ts} {hostname} sshd[{pid}]: "
        f"Failed password for {username} "
        f"from {ip} port {src_port} ssh2"
    )

    return {
        "raw": raw,
        "timestamp": datetime.now().isoformat(),
        "source_ip": ip,
        "destination_ip": get_employee_ip(),
        "source_port": src_port,
        "destination_port": SSH_PORT,
        "username": username,
        "action": "login_fail",
        "protocol": "TCP",
        "bytes_sent": 0,
        "country": get_country(ip),
        "topic": "auth",
    }


def generate_login_success(src_ip: str = None) -> dict:
    """
    Generate a successful SSH login.

    Real log format:
    Jun 13 03:42:13 webserver01 sshd[12494]: Accepted password for alice
    from 192.168.1.10 port 52341 ssh2
    """
    # Successful logins mostly come from internal/employee IPs
    ip = src_ip or (
        get_employee_ip() if random.random() < 0.85
        else get_source_ip(malicious=False)
    )
    username = random.choice(LEGITIMATE_USERS)
    hostname = _hostname()
    pid = random.randint(*PID_RANGE)
    src_port = random.randint(49152, 65535)
    ts = _timestamp()

    raw = (
        f"{ts} {hostname} sshd[{pid}]: "
        f"Accepted password for {username} "
        f"from {ip} port {src_port} ssh2"
    )

    return {
        "raw": raw,
        "timestamp": datetime.now().isoformat(),
        "source_ip": ip,
        "destination_ip": get_employee_ip(),
        "source_port": src_port,
        "destination_port": SSH_PORT,
        "username": username,
        "action": "login_success",
        "protocol": "TCP",
        "bytes_sent": 0,
        "country": get_country(ip),
        "topic": "auth",
    }


def generate_invalid_user(src_ip: str = None) -> dict:
    """
    Generate an invalid user attempt.
    Attackers often try usernames that don't exist.

    Real log format:
    Jun 13 03:42:11 webserver01 sshd[12493]: Invalid user ftp
    from 185.220.101.45 port 54832
    """
    ip = src_ip or get_source_ip(malicious=True)
    username = fake.user_name()
    hostname = _hostname()
    pid = random.randint(*PID_RANGE)
    src_port = random.randint(49152, 65535)
    ts = _timestamp()

    raw = (
        f"{ts} {hostname} sshd[{pid}]: "
        f"Invalid user {username} "
        f"from {ip} port {src_port}"
    )

    return {
        "raw": raw,
        "timestamp": datetime.now().isoformat(),
        "source_ip": ip,
        "destination_ip": get_employee_ip(),
        "source_port": src_port,
        "destination_port": SSH_PORT,
        "username": username,
        "action": "invalid_user",
        "protocol": "TCP",
        "bytes_sent": 0,
        "country": get_country(ip),
        "topic": "auth",
    }


def generate_normal_event() -> dict:
    """
    Generate a random normal auth event.
    Weighted distribution: mostly successes with occasional failures.
    """
    roll = random.random()
    if roll < 0.70:
        return generate_login_success()
    elif roll < 0.90:
        return generate_login_fail()
    else:
        return generate_invalid_user()