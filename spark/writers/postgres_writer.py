import os
import psycopg2
from psycopg2.extras import execute_values

# ============================================================
# PostgreSQL connection configuration
# All values must come from environment variables
# No sensitive defaults — fail loudly if missing
# ============================================================
PG_HOST = os.getenv("POSTGRES_HOST", "postgres")  # safe default
PG_PORT = os.getenv("POSTGRES_PORT", "5432")       # safe default
PG_USER = os.getenv("POSTGRES_USER")               # no default
PG_PASS = os.getenv("POSTGRES_PASSWORD")           # no default
PG_DB   = os.getenv("POSTGRES_DB")                 # no default

# Validate at startup
if not PG_USER or not PG_PASS or not PG_DB:
    raise EnvironmentError(
        "Missing required environment variables: "
        "POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DB. "
        "Check your .env file."
    )

JDBC_URL = f"jdbc:postgresql://{PG_HOST}:{PG_PORT}/{PG_DB}"

JDBC_PROPERTIES = {
    "user":     PG_USER,
    "password": PG_PASS,
    "driver":   "org.postgresql.Driver",
}


def get_connection():
    """
    Create and return a raw psycopg2 connection.
    Used for batch inserts which are faster than JDBC
    for small to medium sized batches.
    """
    return psycopg2.connect(
        host=PG_HOST,
        port=PG_PORT,
        user=PG_USER,
        password=PG_PASS,
        dbname=PG_DB,
    )


def write_alerts(batch_df, batch_id: int):
    """
    Write detected alerts to the alerts table.

    Called by Spark's foreachBatch for every micro-batch
    that contains alert data.

    Parameters:
        batch_df  : Spark DataFrame containing alert rows
        batch_id  : unique ID of this micro-batch (for logging)
    """
    count = batch_df.count()
    if count == 0:
        return

    print(f"[POSTGRES] Writing {count} alerts (batch {batch_id})")

    rows = batch_df.collect()

    records = []
    for row in rows:
        records.append((
            row.timestamp,
            row.source_ip,
            row.destination_ip,
            row.source_port,
            row.destination_port,
            row.username,
            row.topic,
            row.action,
            row.protocol,
            row.bytes_sent,
            row.country,
            row.severity,
            row.rule_triggered,
            row.raw,
        ))

    sql = """
        INSERT INTO alerts (
            timestamp, source_ip, destination_ip,
            source_port, destination_port, username,
            topic, action, protocol, bytes_sent,
            country, severity, rule_triggered, raw
        ) VALUES %s
    """

    try:
        conn = get_connection()
        with conn:
            with conn.cursor() as cur:
                execute_values(cur, sql, records)
        conn.close()
        print(f"[POSTGRES] Successfully wrote {count} alerts")
    except Exception as e:
        print(f"[POSTGRES] Error writing alerts: {e}")
        raise


def write_traffic_stats(batch_df, batch_id: int):
    """
    Write aggregated traffic statistics to traffic_stats table.

    Called every micro-batch with aggregated counts
    per time window, topic, and source IP.
    """
    count = batch_df.count()
    if count == 0:
        return

    print(f"[POSTGRES] Writing {count} traffic stats (batch {batch_id})")

    rows = batch_df.collect()

    records = []
    for row in rows:
        records.append((
            row.window_start,
            row.window_end,
            row.topic,
            row.source_ip,
            row.country,
            row.event_count,
            row.fail_count,
            row.bytes_total,
        ))

    sql = """
        INSERT INTO traffic_stats (
            window_start, window_end, topic,
            source_ip, country, event_count,
            fail_count, bytes_total
        ) VALUES %s
    """

    try:
        conn = get_connection()
        with conn:
            with conn.cursor() as cur:
                execute_values(cur, sql, records)
        conn.close()
        print(f"[POSTGRES] Successfully wrote {count} traffic stats")
    except Exception as e:
        print(f"[POSTGRES] Error writing traffic stats: {e}")
        raise