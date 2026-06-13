# Big Data Security Pipeline
Real-time anomaly detection on security logs using Kafka + Spark Structured Streaming + PostgreSQL + Grafana.

## Stack
- Apache Kafka (ingestion)
- Apache Spark / PySpark (processing)
- PostgreSQL (alert storage)
- Grafana (dashboard)
- Docker Compose (orchestration)

## Structure
bigdata-security-pipeline/

├── producer/          # Python Kafka producer (Person 1)

│   └── producer.py

├── spark/             # PySpark streaming job (Person 2)

│   └── spark_job.py

├── dashboard/         # Grafana provisioning (Person 3)

│   └── grafana_provisioning/

├── docker/            # PostgreSQL init SQL

│   └── init.sql

├── docker-compose.yml # Full stack orchestration

└── .env               # Secrets (never committed)
## Quickstart
```bash
git clone <repo-url>
cp .env.example .env
docker compose up -d
python producer/producer.py
```

## Team
- Person 1 — Ingestion (producer/)
- Person 2 — Traitement (spark/)
- Person 3 — Visualisation (dashboard/ + docker-compose.yml)
