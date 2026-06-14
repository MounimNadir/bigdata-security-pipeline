from pyspark.sql import DataFrame
from pyspark.sql.functions import (
    col, window, count, approx_count_distinct,
    lit, when, max as spark_max
)

WINDOW_DURATION = "1 minute"
SLIDE_DURATION  = "30 seconds"
MED_THRESHOLD   = 20
HIGH_THRESHOLD  = 50


def detect(web_df: DataFrame) -> DataFrame:
    errors = web_df.filter(
        col("action").isin(["http_404", "http_403", "http_500"])
    )

    windowed = (
        errors
        .groupBy(
            window(col("timestamp"), WINDOW_DURATION, SLIDE_DURATION),
            col("source_ip"),
            col("country"),
        )
        .agg(
            count("*").alias("error_count"),
            approx_count_distinct("url").alias("distinct_urls"),
            spark_max("destination_ip").alias("destination_ip"),
            spark_max("source_port").alias("source_port"),
            spark_max("raw").alias("raw"),
        )
        .filter(col("distinct_urls") > MED_THRESHOLD)
    )

    alerts = (
        windowed
        .withColumn("severity",
            when(col("distinct_urls") > HIGH_THRESHOLD, lit("HIGH"))
            .otherwise(lit("MED")))
        .withColumn("rule_triggered",   lit("web_scan"))
        .withColumn("topic",            lit("web"))
        .withColumn("action",           lit("web_scan_detected"))
        .withColumn("protocol",         lit("TCP"))
        .withColumn("bytes_sent",       lit(0).cast("long"))
        .withColumn("username",         lit(None).cast("string"))
        .withColumn("destination_port", lit(80))
        .withColumn("timestamp",        col("window.start"))
        .drop("window", "error_count", "distinct_urls")
    )

    return alerts