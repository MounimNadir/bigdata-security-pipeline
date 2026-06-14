from pyspark.sql import DataFrame
from pyspark.sql.functions import (
    col, window, sum as spark_sum,
    lit, max as spark_max
)

WINDOW_DURATION = "5 minutes"
SLIDE_DURATION  = "1 minute"
BYTES_THRESHOLD = 100_000_000


def detect(firewall_df: DataFrame) -> DataFrame:
    allowed = firewall_df.filter(col("action") == "allow")

    windowed = (
        allowed
        .groupBy(
            window(col("timestamp"), WINDOW_DURATION, SLIDE_DURATION),
            col("source_ip"),
            col("country"),
        )
        .agg(
            spark_sum("bytes_sent").alias("total_bytes"),
            spark_max("destination_ip").alias("destination_ip"),
            spark_max("source_port").alias("source_port"),
            spark_max("destination_port").alias("destination_port"),
            spark_max("raw").alias("raw"),
        )
        .filter(col("total_bytes") > BYTES_THRESHOLD)
    )

    alerts = (
        windowed
        .withColumn("severity",       lit("CRIT"))
        .withColumn("rule_triggered", lit("data_exfiltration"))
        .withColumn("topic",          lit("firewall"))
        .withColumn("action",         lit("exfiltration_detected"))
        .withColumn("protocol",       lit("TCP"))
        .withColumn("bytes_sent",     col("total_bytes"))
        .withColumn("username",       lit(None).cast("string"))
        .withColumn("timestamp",      col("window.start"))
        .drop("window", "total_bytes")
    )

    return alerts