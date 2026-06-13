-- ============================================================
-- Security Pipeline Database Schema
-- ============================================================

-- Table 1: One row per detected anomaly
CREATE TABLE IF NOT EXISTS alerts (
    id                SERIAL PRIMARY KEY,
    timestamp         TIMESTAMP NOT NULL,
    source_ip         VARCHAR(45) NOT NULL,
    destination_ip    VARCHAR(45),
    source_port       INTEGER,
    destination_port  INTEGER,
    username          VARCHAR(100),
    topic             VARCHAR(20) NOT NULL,
    action            VARCHAR(100) NOT NULL,
    protocol          VARCHAR(10),
    bytes_sent        BIGINT DEFAULT 0,
    country           VARCHAR(50),
    severity          VARCHAR(10) NOT NULL,
    rule_triggered    VARCHAR(50) NOT NULL,
    raw               TEXT
);

-- Table 2: Aggregated traffic statistics per time window
CREATE TABLE IF NOT EXISTS traffic_stats (
    id              SERIAL PRIMARY KEY,
    window_start    TIMESTAMP NOT NULL,
    window_end      TIMESTAMP NOT NULL,
    topic           VARCHAR(20) NOT NULL,
    source_ip       VARCHAR(45),
    country         VARCHAR(50),
    event_count     INTEGER DEFAULT 0,
    fail_count      INTEGER DEFAULT 0,
    bytes_total     BIGINT DEFAULT 0
);

-- ============================================================
-- Indexes for Grafana query performance
-- ============================================================

-- Alerts: most queries filter by time
CREATE INDEX idx_alerts_timestamp
    ON alerts(timestamp DESC);

-- Alerts: severity distribution queries
CREATE INDEX idx_alerts_severity
    ON alerts(severity);

-- Alerts: top attacking IPs queries
CREATE INDEX idx_alerts_source_ip
    ON alerts(source_ip);

-- Alerts: filter by which rule fired
CREATE INDEX idx_alerts_rule
    ON alerts(rule_triggered);

-- Traffic stats: time series queries
CREATE INDEX idx_traffic_window
    ON traffic_stats(window_start DESC);

-- Traffic stats: per-topic queries
CREATE INDEX idx_traffic_topic
    ON traffic_stats(topic);

-- ============================================================
-- Severity check constraint
-- ============================================================
ALTER TABLE alerts
    ADD CONSTRAINT chk_severity
    CHECK (severity IN ('LOW', 'MED', 'HIGH', 'CRIT'));

-- ============================================================
-- Confirmation message
-- ============================================================
DO $$
BEGIN
    RAISE NOTICE 'Security pipeline schema created successfully.';
END $$;