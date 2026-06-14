from pyspark.sql import DataFrame
from pyspark.sql.functions import (
    col, from_json, when, lit, to_timestamp
)
from pyspark.sql.types import (
    StructType, StructField,
    StringType, IntegerType, LongType
)

WEB_SCHEMA = StructType([
    StructField("raw",              StringType(),  True),
    StructField("timestamp",        StringType(),  True),
    StructField("source_ip",        StringType(),  True),
    StructField("destination_ip",   StringType(),  True),
    StructField("source_port",      IntegerType(), True),
    StructField("destination_port", IntegerType(), True),
    StructField("username",         StringType(),  True),
    StructField("action",           StringType(),  True),
    StructField("protocol",         StringType(),  True),
    StructField("bytes_sent",       LongType(),    True),
    StructField("country",          StringType(),  True),
    StructField("topic",            StringType(),  True),
    StructField("url",              StringType(),  True),
    StructField("http_method",      StringType(),  True),
    StructField("http_status",      IntegerType(), True),
])


def parse_web_stream(raw_df: DataFrame) -> DataFrame:
    parsed = (
        raw_df
        .select(
            from_json(
                col("value").cast("string"),
                WEB_SCHEMA
            ).alias("data")
        )
        .select("data.*")
    )

    result = (
        parsed
        .withColumn("timestamp",
            to_timestamp(col("timestamp")))
        .withColumn("bytes_sent",
            when(col("bytes_sent").isNull(), lit(0))
            .otherwise(col("bytes_sent")))
        .withColumn("http_status",
            when(col("http_status").isNull(), lit(0))
            .otherwise(col("http_status")))
        .withColumn("country",
            when(col("country").isNull(), lit("UNKNOWN"))
            .otherwise(col("country")))
        .filter(col("source_ip").isNotNull())
        .filter(col("action").isNotNull())
        .filter(col("timestamp").isNotNull())
    )

    return result