import os
import json
import time
import random
import threading
from kafka import KafkaProducer

from generators.auth_generator import generate_normal_event as auth_event
from generators.firewall_generator import generate_normal_event as firewall_event
from generators.web_generator import generate_normal_event as web_event
from attackers import brute_force, port_scan, web_scan, exfiltration, lateral_movement

# ============================================================
# Configuration from environment variables
# ============================================================
KAFKA_BROKER         = os.getenv("KAFKA_BROKER", "kafka:9092")
TOPIC_AUTH           = os.getenv("KAFKA_TOPIC_AUTH", "auth-logs")
TOPIC_FIREWALL       = os.getenv("KAFKA_TOPIC_FIREWALL", "firewall-logs")
TOPIC_WEB            = os.getenv("KAFKA_TOPIC_WEB", "web-logs")
RATE_AUTH            = int(os.getenv("PRODUCER_RATE_AUTH", "5"))
RATE_FIREWALL        = int(os.getenv("PRODUCER_RATE_FIREWALL", "15"))
RATE_WEB             = int(os.getenv("PRODUCER_RATE_WEB", "10"))
ATTACK_INTERVAL_MIN  = int(os.getenv("ATTACK_INTERVAL_MIN", "30"))
ATTACK_INTERVAL_MAX  = int(os.getenv("ATTACK_INTERVAL_MAX", "60"))


# ============================================================
# Kafka Producer setup
# ============================================================
def create_producer() -> KafkaProducer:
    """
    Create and return a Kafka producer.
    Retries on connection failure — Kafka may not be
    immediately ready when this container starts.
    """
    while True:
        try:
            producer = KafkaProducer(
                bootstrap_servers=KAFKA_BROKER,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                # How many events to buffer before forcing a send
                batch_size=16384,
                # Wait up to 10ms to fill a batch (reduces network calls)
                linger_ms=10,
                # Retry failed sends up to 5 times
                retries=5,
                # Require acknowledgment from Kafka leader
                acks="all",
            )
            print(f"[PRODUCER] Connected to Kafka at {KAFKA_BROKER}")
            return producer
        except Exception as e:
            print(f"[PRODUCER] Kafka not ready yet: {e}. Retrying in 5s...")
            time.sleep(5)


# ============================================================
# Generator threads
# Each runs independently at its own rate
# ============================================================
def run_generator(producer: KafkaProducer,
                  generator_fn,
                  topic: str,
                  rate: int,
                  name: str):
    """
    Continuously generate events at a given rate.

    rate = events per second
    sleep = 1 / rate seconds between events
    """
    sleep_interval = 1.0 / rate
    print(f"[{name}] Starting at {rate} events/second → topic: {topic}")

    while True:
        try:
            event = generator_fn()
            producer.send(topic, value=event)
        except Exception as e:
            print(f"[{name}] Error generating event: {e}")
        time.sleep(sleep_interval)


# ============================================================
# Attack scheduler
# Randomly fires one attack scenario every N seconds
# ============================================================
def run_attack_scheduler(producer: KafkaProducer):
    """
    Periodically inject one of the 5 attack scenarios.
    The interval is randomized to simulate realistic
    unpredictable attack timing.
    """
    print("[SCHEDULER] Attack scheduler started")

    # All available attack scenarios
    scenarios = [
        {
            "name": "brute_force",
            "fn": lambda: brute_force.run(producer, TOPIC_AUTH),
        },
        {
            "name": "port_scan",
            "fn": lambda: port_scan.run(producer, TOPIC_FIREWALL),
        },
        {
            "name": "web_scan",
            "fn": lambda: web_scan.run(producer, TOPIC_WEB),
        },
        {
            "name": "exfiltration",
            "fn": lambda: exfiltration.run(producer, TOPIC_FIREWALL),
        },
        {
            "name": "lateral_movement",
            "fn": lambda: lateral_movement.run(
                producer, TOPIC_AUTH, TOPIC_FIREWALL
            ),
        },
    ]

    while True:
        # Wait a random interval before next attack
        interval = random.randint(ATTACK_INTERVAL_MIN, ATTACK_INTERVAL_MAX)
        print(f"[SCHEDULER] Next attack in {interval} seconds")
        time.sleep(interval)

        # Pick a random scenario
        scenario = random.choice(scenarios)
        print(f"[SCHEDULER] Launching attack: {scenario['name']}")

        try:
            result = scenario["fn"]()
            print(f"[SCHEDULER] Attack complete: {result}")
        except Exception as e:
            print(f"[SCHEDULER] Attack failed: {e}")


# ============================================================
# Main entry point
# ============================================================
def main():
    print("=" * 60)
    print("  Real-Time Security Event Producer")
    print("  Connecting to Kafka...")
    print("=" * 60)

    producer = create_producer()

    # Start the three generator threads
    threads = [
        threading.Thread(
            target=run_generator,
            args=(producer, auth_event, TOPIC_AUTH, RATE_AUTH, "AUTH"),
            daemon=True,
        ),
        threading.Thread(
            target=run_generator,
            args=(producer, firewall_event, TOPIC_FIREWALL,
                  RATE_FIREWALL, "FIREWALL"),
            daemon=True,
        ),
        threading.Thread(
            target=run_generator,
            args=(producer, web_event, TOPIC_WEB, RATE_WEB, "WEB"),
            daemon=True,
        ),
        # Attack scheduler runs in its own thread
        threading.Thread(
            target=run_attack_scheduler,
            args=(producer,),
            daemon=True,
        ),
    ]

    for thread in threads:
        thread.start()

    print("[PRODUCER] All generators running. Press Ctrl+C to stop.")

    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[PRODUCER] Shutting down...")
        producer.flush()
        producer.close()


if __name__ == "__main__":
    main()