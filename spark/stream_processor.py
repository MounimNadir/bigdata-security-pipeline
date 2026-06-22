import os
from pyspark.sql import SparkSession
from pyspark.sql.functions import (
    col, window, count, sum as spark_sum,
    max as spark_max, lit, when
)

from parsers import (
    parse_auth_stream,
    parse_firewall_stream,
    parse_web_stream,
)
from detectors import (
    detect_brute_force,
    detect_port_scan,
    detect_web_scan,
    detect_exfiltration,
    detect_lateral_movement,
)
from writers import write_alerts, write_traffic_stats, write_parquet

# ============================================================
# Configuration — all from environment variables
# No sensitive defaults
# ============================================================
KAFKA_BROKER   = os.getenv("KAFKA_BROKER",         "kafka:9092")
TOPIC_AUTH     = os.getenv("KAFKA_TOPIC_AUTH",     "auth-logs")
TOPIC_FIREWALL = os.getenv("KAFKA_TOPIC_FIREWALL", "firewall-logs")
TOPIC_WEB      = os.getenv("KAFKA_TOPIC_WEB",      "web-logs")
BATCH_INTERVAL = os.getenv("SPARK_BATCH_INTERVAL", "10")

# PostgreSQL — sensitive, no defaults
PG_HOST = os.getenv("POSTGRES_HOST", "postgres")
PG_PORT = os.getenv("POSTGRES_PORT", "5432")
PG_USER = os.getenv("POSTGRES_USER")
PG_PASS = os.getenv("POSTGRES_PASSWORD")
PG_DB   = os.getenv("POSTGRES_DB")

# Validate sensitive variables at startup
if not PG_USER or not PG_PASS or not PG_DB:
    raise EnvironmentError(
        "Missing required environment variables: "
        "POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DB. "
        "Check your .env file."
    )

JDBC_URL = f"jdbc:postgresql://{PG_HOST}:{PG_PORT}/{PG_DB}"


def create_spark_session() -> SparkSession:
    """
    Create and configure the Spark session.
    """
    return (
        SparkSession.builder
        .appName("SecurityPipeline")
        .config("spark.sql.shuffle.partitions", "4")
        .config(
            "spark.sql.streaming.checkpointLocation",
            "/app/data/checkpoints"
        )
        .config(
            "spark.sql.streaming.watermarkDelayThreshold",
            "10 seconds"
        )
        .getOrCreate()
    )


def read_kafka_stream(spark: SparkSession, topic: str):
    """
    Read a Kafka topic as a Spark Structured Stream.

    startingOffsets=latest means we only process
    new messages, not replay historical ones.
    """
    return (
        spark.readStream
        .format("kafka")
        .option("kafka.bootstrap.servers", KAFKA_BROKER)
        .option("subscribe", topic)
        .option("startingOffsets", "latest")
        .option("maxOffsetsPerTrigger", "1000")
        .option("failOnDataLoss", "false")
        .load()
    )


def build_alerts_union(auth_df, firewall_df, web_df):
    """
    Apply all 5 detection rules and union results
    into a single alerts DataFrame.

    Each detector returns the same schema so they
    can be unioned cleanly.
    """
    alert_cols = [
        "timestamp", "source_ip", "destination_ip",
        "source_port", "destination_port", "username",
        "topic", "action", "protocol", "bytes_sent",
        "country", "severity", "rule_triggered", "raw"
    ]

    brute_force_alerts = detect_brute_force(auth_df).select(alert_cols)
    port_scan_alerts   = detect_port_scan(firewall_df).select(alert_cols)
    web_scan_alerts    = detect_web_scan(web_df).select(alert_cols)
    exfil_alerts       = detect_exfiltration(firewall_df).select(alert_cols)
    lateral_alerts     = detect_lateral_movement(firewall_df).select(alert_cols)

    all_alerts = (
        brute_force_alerts
        .union(port_scan_alerts)
        .union(web_scan_alerts)
        .union(exfil_alerts)
        .union(lateral_alerts)
    )

    return all_alerts


def build_traffic_stats(auth_df, firewall_df, web_df):
    """
    Build aggregated traffic statistics for Grafana charts.

    Groups events by 1-minute windows, topic, source IP,
    and country to power the time series charts.
    """
    STATS_WINDOW = "1 minute"

    def stats_for(df, topic_name: str):
        return (
            df
            .groupBy(
                window(col("timestamp"), STATS_WINDOW),
                col("source_ip"),
                col("country"),
            )
            .agg(
                count("*").alias("event_count"),
                spark_sum(
                    when(col("action").contains("fail"), 1)
                    .otherwise(0)
                ).alias("fail_count"),
                spark_sum("bytes_sent").alias("bytes_total"),
            )
            .withColumn("topic",        lit(topic_name))
            .withColumn("window_start", col("window.start"))
            .withColumn("window_end",   col("window.end"))
            .drop("window")
        )

    auth_stats     = stats_for(auth_df,     "auth")
    firewall_stats = stats_for(firewall_df, "firewall")
    web_stats      = stats_for(web_df,      "web")

    return auth_stats.union(firewall_stats).union(web_stats)


def main():
    print("=" * 60)
    print("  Security Pipeline — Spark Structured Streaming")
    print("  Starting up...")
    print("=" * 60)

    spark = create_spark_session()
    spark.sparkContext.setLogLevel("WARN")

    print("[SPARK] Session created successfully")

    # --------------------------------------------------------
    # Step 1: Read from all 3 Kafka topics
    # --------------------------------------------------------
    raw_auth     = read_kafka_stream(spark, TOPIC_AUTH)
    raw_firewall = read_kafka_stream(spark, TOPIC_FIREWALL)
    raw_web      = read_kafka_stream(spark, TOPIC_WEB)

    print("[SPARK] Connected to all 3 Kafka topics")

    # --------------------------------------------------------
    # Step 2: Parse each stream
    # --------------------------------------------------------
    auth_df     = parse_auth_stream(raw_auth)
    firewall_df = parse_firewall_stream(raw_firewall)
    web_df      = parse_web_stream(raw_web)

    # Add watermark for windowed aggregations
    # Tells Spark how late arriving events can be
    auth_df     = auth_df.withWatermark("timestamp",     "5 seconds")
    firewall_df = firewall_df.withWatermark("timestamp", "5 seconds")
    web_df      = web_df.withWatermark("timestamp",      "5 seconds")

    print("[SPARK] Parsers configured")

    # --------------------------------------------------------
    # Step 3: Build detection queries
    # --------------------------------------------------------
    all_alerts    = build_alerts_union(auth_df, firewall_df, web_df)
    traffic_stats = build_traffic_stats(auth_df, firewall_df, web_df)

    print("[SPARK] Detection rules configured")

    # --------------------------------------------------------
    # Step 4: Write alerts to PostgreSQL
    # --------------------------------------------------------
    alerts_query = (
        all_alerts.writeStream
        .outputMode("append")
        .foreachBatch(write_alerts)
        .trigger(processingTime=f"{BATCH_INTERVAL} seconds")
        .option(
            "checkpointLocation",
            "/app/data/checkpoints/alerts"
        )
        .start()
    )

    # --------------------------------------------------------
    # Step 5: Write traffic stats to PostgreSQL
    # --------------------------------------------------------
    stats_query = (
        traffic_stats.writeStream
        .outputMode("append")
        .foreachBatch(write_traffic_stats)
        .trigger(processingTime=f"{BATCH_INTERVAL} seconds")
        .option(
            "checkpointLocation",
            "/app/data/checkpoints/stats"
        )
        .start()
    )

    # --------------------------------------------------------
    # Step 6: Write raw events to Parquet archive
    # --------------------------------------------------------
    auth_parquet_query = (
        auth_df.writeStream
        .outputMode("append")
        .foreachBatch(
            lambda df, bid: write_parquet(df, bid, "auth")
        )
        .trigger(processingTime=f"{BATCH_INTERVAL} seconds")
        .option(
            "checkpointLocation",
            "/app/data/checkpoints/parquet_auth"
        )
        .start()
    )

    firewall_parquet_query = (
        firewall_df.writeStream
        .outputMode("append")
        .foreachBatch(
            lambda df, bid: write_parquet(df, bid, "firewall")
        )
        .trigger(processingTime=f"{BATCH_INTERVAL} seconds")
        .option(
            "checkpointLocation",
            "/app/data/checkpoints/parquet_firewall"
        )
        .start()
    )

    web_parquet_query = (
        web_df.writeStream
        .outputMode("append")
        .foreachBatch(
            lambda df, bid: write_parquet(df, bid, "web")
        )
        .trigger(processingTime=f"{BATCH_INTERVAL} seconds")
        .option(
            "checkpointLocation",
            "/app/data/checkpoints/parquet_web"
        )
        .start()
    )

    print("[SPARK] All streaming queries started")
    print(f"[SPARK] Processing every {BATCH_INTERVAL} seconds")
    print("[SPARK] Spark UI available at http://localhost:4040")
    print("[SPARK] Waiting for data...")

    # Keep the job running forever
    spark.streams.awaitAnyTermination()


if __name__ == "__main__":
    main()