# Big Data Security Pipeline — Real-Time IDS

A fully containerised Intrusion Detection System (IDS) that simulates network and authentication logs, streams them through Apache Kafka, processes them with Spark Structured Streaming to detect attacks in real time, stores results in PostgreSQL, and visualises everything in a live Grafana dashboard.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    PRODUCER                         │
│  generators/ ──► attackers/ ──► utils/              │
│  (SSH logs)     (Brute force,   (IP pool,           │
│  (Firewall logs) Port scan,      GeoIP lookup)      │
│  (Web logs)     Exfiltration,                       │
│                 Lateral movement)                   │
└───────────────────┬─────────────────────────────────┘
                    │ Kafka messages (JSON)
                    ▼
┌─────────────────────────────────────────────────────┐
│              APACHE KAFKA 3.9 (KRaft)               │
│  ├── auth-logs       (3 partitions, 7d retention)   │
│  ├── firewall-logs   (3 partitions, 7d retention)   │
│  └── web-logs        (3 partitions, 7d retention)   │
└───────────────────┬─────────────────────────────────┘
                    │ Structured Streaming
                    ▼
┌─────────────────────────────────────────────────────┐
│           SPARK STRUCTURED STREAMING 3.5            │
│  parsers/    → regex parse per log format           │
│  detectors/  → 5 anomaly detection rules            │
│  writers/    → PostgreSQL sink + Parquet archive    │
└──────────────┬──────────────────────┬───────────────┘
               │                      │
               ▼                      ▼
     ┌──────────────────┐    ┌──────────────────┐
     │    POSTGRESQL    │    │  PARQUET FILES   │
     │  alerts          │    │  data/parquet/   │
     │  traffic_stats   │    │  auth/           │
     └────────┬─────────┘    │  firewall/       │
              │              │  web/            │
              ▼              └──────────────────┘
     ┌──────────────────┐
     │     GRAFANA      │
     │  localhost:3000  │
     │  Live dashboard  │
     └──────────────────┘
```

---

## Detection Rules

| Rule | Kafka Topic | Trigger Condition | Severity |
|---|---|---|---|
| SSH Brute Force | auth-logs | > 5 failed logins from same IP in 1 min | HIGH / CRIT |
| Port Scan | firewall-logs | > 10 distinct destination ports from same IP in 1 min | HIGH |
| Web Scanner | web-logs | > 20 distinct URLs + > 50% 404 responses from same IP in 1 min | MED / HIGH |
| Data Exfiltration | firewall-logs | > 100 MB sent from same IP in 5 min | CRIT |
| Lateral Movement | firewall-logs | > 5 distinct internal destination IPs from same internal IP in 2 min | CRIT |

Severity escalates automatically: e.g., brute force goes from HIGH (>5 failures) to CRIT (>10 failures).

---

## Services

| Service | Image | Port | Purpose |
|---|---|---|---|
| `kafka` | `apache/kafka:3.9.0` | 9092, 29092 | Message broker (KRaft, no Zookeeper) |
| `kafka-init` | `apache/kafka:3.9.0` | — | One-shot topic creation, exits when done |
| `kafka-ui` | `provectuslabs/kafka-ui` | 8080 | Web UI to browse Kafka topics and messages |
| `postgres` | `postgres:16` | 5432 | Persistent alert and stats storage |
| `producer` | `./producer/Dockerfile` | — | Log simulation + attack injection |
| `spark` | `./spark/Dockerfile` | 4040 | Stream processing + anomaly detection |
| `grafana` | `grafana/grafana:10.4.0` | 3000 | Live security dashboard |

---

## Project Structure

```
bigdata-security-pipeline/
│
├── producer/                        # Log simulation service
│   ├── Dockerfile
│   ├── producer.py                  # Main loop — spins up generators + attackers
│   ├── generators/
│   │   ├── auth_generator.py        # Simulates SSH auth logs
│   │   ├── firewall_generator.py    # Simulates firewall/network logs
│   │   └── web_generator.py         # Simulates HTTP web server logs
│   ├── attackers/
│   │   ├── brute_forcer.py          # SSH brute force attack simulation
│   │   ├── port_scanner.py          # Port scan simulation
│   │   ├── web_scanner.py           # Web vulnerability scan simulation
│   │   ├── exfiltrator.py           # Data exfiltration simulation
│   │   └── lateral_mover.py         # Lateral movement simulation
│   ├── utils/
│   │   ├── ip_pool.py               # RFC-1918 internal + external IP generation
│   │   └── geoip.py                 # GeoIP country lookup (requires mmdb file)
│   └── requirements.txt
│
├── spark/                           # Stream processing service
│   ├── Dockerfile
│   ├── stream_processor.py          # Main Spark entry point
│   ├── parsers/
│   │   ├── auth_parser.py           # Regex parse for auth log format
│   │   ├── firewall_parser.py       # Regex parse for firewall log format
│   │   └── web_parser.py            # Regex parse for web log format
│   ├── detectors/
│   │   ├── brute_force_detector.py  # Windowed failed login counter
│   │   ├── port_scan_detector.py    # Windowed distinct port counter
│   │   ├── web_scan_detector.py     # Windowed URL + 404 rate analysis
│   │   ├── exfiltration_detector.py # Windowed bytes-sent aggregation
│   │   └── lateral_movement_detector.py # Windowed distinct internal IP counter
│   ├── writers/
│   │   ├── alert_writer.py          # foreachBatch → PostgreSQL alerts table
│   │   ├── stats_writer.py          # foreachBatch → PostgreSQL traffic_stats table
│   │   └── parquet_writer.py        # Raw event archive to local Parquet files
│   └── requirements.txt
│
├── dashboard/
│   └── grafana/
│       ├── provisioning/
│       │   ├── datasources/
│       │   │   └── postgres.yml     # Auto-provisions PostgreSQL datasource
│       │   └── dashboards/
│       │       └── dashboard.yml    # Tells Grafana where to find dashboard JSON
│       └── dashboards/
│           └── security.json        # Full dashboard definition (9 panels)
│
├── postgres/
│   └── init.sql                     # Creates alerts + traffic_stats tables + indexes
│
├── data/
│   ├── blacklist.txt                # Known malicious IPs used by attackers
│   ├── usernames.txt                # Username wordlist for brute force simulation
│   └── parquet/                     # Raw event archive (written by Spark)
│       ├── auth/
│       ├── firewall/
│       └── web/
│
├── docker-compose.yml
└── .env                             # All configuration (credentials, rates, etc.)
```

---

## Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Docker Engine 24+ with Compose v2)
- At least **6 GB of RAM** allocated to Docker (Spark needs 2 GB driver + 2 GB executor)
- Ports 3000, 4040, 5432, 8080, 9092, 29092 free on your machine

---

## Running the Pipeline

### 1. Clone the repository

```bash
git clone https://github.com/MounimNadir/bigdata-security-pipeline.git
cd bigdata-security-pipeline
```

### 2. Review the configuration

All settings are in `.env`. The defaults work out of the box — no changes needed to run locally:

```env
# PostgreSQL
POSTGRES_USER=secadmin
POSTGRES_PASSWORD=secpass123
POSTGRES_DB=securitydb

# Kafka topics
KAFKA_TOPIC_AUTH=auth-logs
KAFKA_TOPIC_FIREWALL=firewall-logs
KAFKA_TOPIC_WEB=web-logs

# Producer rates (events per second)
PRODUCER_RATE_AUTH=5
PRODUCER_RATE_FIREWALL=15
PRODUCER_RATE_WEB=10

# Grafana
GRAFANA_ADMIN_USER=admin
GRAFANA_ADMIN_PASSWORD=admin123
```

### 3. Build and start all services

```bash
docker compose up -d --build
```

This single command:
1. Builds the `producer` and `spark` Docker images (downloads JARs on first build — takes ~3–5 minutes)
2. Starts Kafka in KRaft mode
3. Runs `kafka-init` to create the three topics, then exits
4. Starts PostgreSQL and runs `init.sql` to create the schema
5. Starts the producer (begins generating logs immediately)
6. Starts Spark (begins consuming from Kafka and detecting attacks)
7. Starts Grafana with the pre-provisioned dashboard

### 4. Wait for all services to become healthy

```bash
docker compose ps
```

Wait until every service shows `healthy` or `running`. This typically takes **30–60 seconds** after the build completes. Spark may take an additional 30 seconds to connect to Kafka on the first start.

### 5. Verify data is flowing

Check that Spark is producing alerts:

```bash
docker compose logs spark --tail 50
```

You should see lines like `Batch X completed` and no error stack traces.

---

## Viewing Results

### Grafana Dashboard — `http://localhost:3000`

**Login:** `admin` / `admin123`

The dashboard opens automatically as the home page. It refreshes every 10 seconds and contains:

| Panel | Type | Description |
|---|---|---|
| Total Alerts | Stat | Count of all triggered alerts |
| Critical Alerts | Stat | Count of CRIT-severity alerts |
| Events Processed | Stat | Total log events ingested |
| Total Bytes Transferred | Stat | Cumulative bytes from firewall logs |
| Alerts by Detection Rule | Bar chart | Which rules are firing most |
| Alerts by Severity | Bar chart | LOW / MED / HIGH / CRIT distribution |
| Events Over Time by Topic | Time series | Auth / Firewall / Web event rates |
| Bytes Transferred Over Time | Time series | Network traffic volume over time |
| Recent Alerts | Table | Last 50 alerts with IP, country, rule, severity |

### Kafka UI — `http://localhost:8080`

Browse topics, inspect individual messages, and monitor consumer group lag. Useful for confirming the producer is sending data and Spark is consuming it.

### Spark UI — `http://localhost:4040`

View active streaming queries, batch durations, input rates, and processing time. Useful for performance monitoring and debugging.

### PostgreSQL (direct query)

```bash
docker compose exec postgres psql -U secadmin -d securitydb
```

```sql
-- How many alerts by rule?
SELECT rule_triggered, severity, COUNT(*) FROM alerts GROUP BY rule_triggered, severity ORDER BY COUNT(*) DESC;

-- Traffic stats summary
SELECT topic, SUM(event_count) AS events, SUM(bytes_total) AS bytes FROM traffic_stats GROUP BY topic;

-- Most recent alerts
SELECT timestamp, source_ip, country, rule_triggered, severity FROM alerts ORDER BY timestamp DESC LIMIT 20;
```

---

## Stopping the Pipeline

```bash
# Stop all containers (data is preserved in Docker volumes)
docker compose down

# Stop and delete all data (volumes, networks)
docker compose down -v
```

---

## Rebuilding After Code Changes

If you edit any Python file in `producer/` or `spark/`, rebuild that service:

```bash
# Rebuild and restart only the spark service
docker compose up -d --build spark

# Rebuild and restart only the producer service
docker compose up -d --build producer
```

---

## Troubleshooting

**Spark crashes on startup (`spark-submit: not found`)**
The Spark container runs as root. Use the absolute path `/opt/spark/bin/spark-submit` in the Dockerfile CMD — the `spark` user's PATH is not inherited by root.

**`MULTIPLE_WATERMARK_OPERATORS` AnalysisException**
Spark 3.5 rejects applying `withWatermark` twice on the same DataFrame in the same streaming plan. Each source DataFrame should have `withWatermark` applied exactly once, before being passed to any aggregation function.

**Grafana shows "Failed to load home dashboard"**
The `dashboard/grafana/dashboards/security.json` file must not be empty. After editing Grafana files, restart the container: `docker compose restart grafana`.

**Kafka connection refused on first start**
The `kafka-init` container creates topics and exits. If Spark or the producer starts before `kafka-init` completes, they will retry automatically. Wait 60 seconds and check `docker compose ps`.

**No alerts appearing after several minutes**
Attacks are injected on a random interval (`ATTACK_INTERVAL_MIN` to `ATTACK_INTERVAL_MAX` seconds, default 30–60 s). Wait at least 2 minutes for the first attack cycle. Confirm the producer is running: `docker compose logs producer --tail 20`.
