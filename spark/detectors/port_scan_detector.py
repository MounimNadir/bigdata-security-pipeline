from pyspark.sql import DataFrame
from pyspark.sql.functions import (
    col, window, approx_count_distinct, lit, max as spark_max
)

WINDOW_DURATION = "1 minute"
SLIDE_DURATION  = "30 seconds"
PORT_THRESHOLD  = 10


def detect(firewall_df: DataFrame) -> DataFrame:
    blocked = firewall_df.filter(col("action") == "block")

    windowed = (
        blocked
        .groupBy(
            window(col("timestamp"), WINDOW_DURATION, SLIDE_DURATION),
            col("source_ip"),
            col("country"),
        )
        .agg(
            approx_count_distinct("destination_port").alias("distinct_ports"),
            spark_max("destination_ip").alias("destination_ip"),
            spark_max("source_port").alias("source_port"),
            spark_max("raw").alias("raw"),
        )
        .filter(col("distinct_ports") > PORT_THRESHOLD)
    )

    alerts = (
        windowed
        .withColumn("severity",         lit("HIGH"))
        .withColumn("rule_triggered",   lit("port_scan"))
        .withColumn("topic",            lit("firewall"))
        .withColumn("action",           lit("port_scan_detected"))
        .withColumn("protocol",         lit("TCP"))
        .withColumn("bytes_sent",       lit(0).cast("long"))
        .withColumn("username",         lit(None).cast("string"))
        .withColumn("destination_port", lit(0))
        .withColumn("timestamp",        col("window.start"))
        .drop("window", "distinct_ports")
    )

    return alerts