# Big Data Security Pipeline

Real-time anomaly detection on security logs using Kafka + Spark Structured Streaming + PostgreSQL + Grafana.

## Stack
- Apache Kafka KRaft (ingestion — no Zookeeper)
- Apache Spark / PySpark (Structured Streaming processing)
- PostgreSQL (alerts + traffic_stats storage)
- Grafana (live security dashboard)
- Docker Compose (full stack orchestration)

## Architecture
Python Producer

├── generators/     → SSH / Firewall / Web log simulation

├── attackers/      → Brute force / Port scan / Web scan / Exfiltration / Lateral movement

└── utils/          → IP pool + GeoIP lookup

↓

Apache Kafka (KRaft)

├── topic: auth-logs       (3 partitions, 7 day retention)

├── topic: firewall-logs   (3 partitions, 7 day retention)

└── topic: web-logs        (3 partitions, 7 day retention)

↓

Spark Structured Streaming

├── parsers/        → regex parse per log format

├── detectors/      → 5 anomaly detection rules

└── writers/        → PostgreSQL + Parquet sink

↓

┌─────────────────────┐

│     PostgreSQL       │     Parquet (raw archive)

│  alerts             │     data/parquet/auth/

│  traffic_stats      │     data/parquet/firewall/

└─────────────────────┘     data/parquet/web/

↓

Grafana Dashboard (localhost:3000)

├── Panel 1: Live Alert Feed

├── Panel 2: Events Per Second

├── Panel 3: Top Attacking IPs

├── Panel 4: Severity Distribution

├── Panel 5: Attack Timeline

├── Panel 6: Top Targeted Ports

├── Panel 7: Top Targeted Usernames

└── Panel 8: Events by Country (GeoIP)
## Detection Rules
| Rule | Source | Condition | Severity |
|------|--------|-----------|----------|
| SSH Brute Force | auth-logs | >5 login_fail same IP / 1 min | HIGH / CRIT |
| Port Scan | firewall-logs | >10 distinct ports same IP / 1 min | HIGH |
| Web Scanner | web-logs | >20 distinct URLs + >50% 404 / 1 min | MED / HIGH |
| Data Exfiltration | firewall + auth | >100MB sent same IP / 5 min | CRIT |
| Lateral Movement | firewall + auth | >5 internal IPs same IP / 2 min | CRIT |

## Services
| Service | Image | Port |
|---------|-------|------|
| kafka | bitnami/kafka (KRaft) | 9092 / 29092 |
| kafka-init | bitnami/kafka | — |
| kafka-ui | provectuslabs/kafka-ui | 8080 |
| postgres | postgres:16 | 5432 |
| producer | ./producer/Dockerfile | — |
| spark | ./spark/Dockerfile | 4040 |
| grafana | grafana/grafana | 3000 |

## Project Structure
bigdata-security-pipeline/

├── producer/                  # Person 1 — Ingestion

│   ├── Dockerfile

│   ├── producer.py

│   ├── generators/

│   ├── attackers/

│   └── utils/

├── spark/                     # Person 2 — Traitement

│   ├── Dockerfile

│   ├── stream_processor.py

│   ├── parsers/

│   ├── detectors/

│   └── writers/

├── dashboard/                 # Person 3 — Visualisation

│   └── grafana/

│       ├── provisioning/

│       └── dashboards/

├── postgres/

│   └── init.sql

├── data/

│   ├── blacklist.txt

│   ├── usernames.txt

│   └── parquet/

├── docker-compose.yml

└── .env

## Quickstart
```bash
git clone https://github.com/MounimNadir/bigdata-security-pipeline.git
cd bigdata-security-pipeline
cp .env.example .env
docker compose up -d
# wait ~30 seconds for all services to be healthy
python producer/producer.py
# open http://localhost:3000 → admin/changeme
```

## Team
- Person 1 — Ingestion (producer/)
- Person 2 — Traitement (spark/)
- Person 3 — Visualisation (dashboard/ + docker-compose.yml)

## GeoIP Setup
Download GeoLite2-Country.mmdb from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
Place it at: data/GeoLite2-Country.mmdb
(file is gitignored — each team member downloads their own copy)
