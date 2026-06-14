from pyspark.sql import DataFrame
from pyspark.sql.functions import (
    col, window, count, lit, when, max as spark_max
)

WINDOW_DURATION = "1 minute"
SLIDE_DURATION  = "30 seconds"
HIGH_THRESHOLD  = 5
CRIT_THRESHOLD  = 10


def detect(auth_df: DataFrame) -> DataFrame:
    failures = auth_df.filter(col("action").isin(["login_fail", "invalid_user"]))

    windowed = (
        failures
        .groupBy(
            window(col("timestamp"), WINDOW_DURATION, SLIDE_DURATION),
            col("source_ip"),
            col("country"),
        )
        .agg(
            count("*").alias("fail_count"),
            spark_max("raw").alias("raw"),
            spark_max("destination_ip").alias("destination_ip"),
            spark_max("destination_port").alias("destination_port"),
            spark_max("source_port").alias("source_port"),
            spark_max("username").alias("username"),
        )
        .filter(col("fail_count") > HIGH_THRESHOLD)
    )

    alerts = (
        windowed
        .withColumn("severity",
            when(col("fail_count") > CRIT_THRESHOLD, lit("CRIT"))
            .otherwise(lit("HIGH")))
        .withColumn("rule_triggered", lit("brute_force"))
        .withColumn("topic",          lit("auth"))
        .withColumn("action",         lit("login_fail"))
        .withColumn("protocol",       lit("TCP"))
        .withColumn("bytes_sent",     lit(0).cast("long"))
        .withColumn("timestamp",      col("window.start"))
        .drop("window", "fail_count")
    )

    return alerts