from pyspark.sql import DataFrame
from pyspark.sql.functions import (
    col, window, approx_count_distinct,
    lit, max as spark_max
)

WINDOW_DURATION = "1 minute"
SLIDE_DURATION  = "20 seconds"
HOST_THRESHOLD  = 5


def detect(firewall_df: DataFrame) -> DataFrame:
    internal = firewall_df.filter(
        col("source_ip").startswith("10.") |
        col("source_ip").startswith("192.168.") |
        col("source_ip").rlike(r"^172\.(1[6-9]|2[0-9]|3[01])\.")
    )

    windowed = (
        internal
        .groupBy(
            window(col("timestamp"), WINDOW_DURATION, SLIDE_DURATION),
            col("source_ip"),
            col("country"),
        )
        .agg(
            approx_count_distinct("destination_ip").alias("distinct_hosts"),
            spark_max("source_port").alias("source_port"),
            spark_max("destination_ip").alias("destination_ip"),
            spark_max("destination_port").alias("destination_port"),
            spark_max("raw").alias("raw"),
        )
        .filter(col("distinct_hosts") > HOST_THRESHOLD)
    )

    alerts = (
        windowed
        .withColumn("severity",         lit("CRIT"))
        .withColumn("rule_triggered",   lit("lateral_movement"))
        .withColumn("topic",            lit("firewall"))
        .withColumn("action",           lit("lateral_movement_detected"))
        .withColumn("protocol",         lit("TCP"))
        .withColumn("bytes_sent",       lit(0).cast("long"))
        .withColumn("username",         lit(None).cast("string"))
        .withColumn("timestamp",        col("window.start"))
        .drop("window", "distinct_hosts")
    )

    return alerts