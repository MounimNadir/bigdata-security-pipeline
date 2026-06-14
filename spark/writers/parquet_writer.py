import os

PARQUET_BASE = os.getenv("PARQUET_OUTPUT_PATH", "/app/data/parquet")


def write_parquet(batch_df, batch_id: int, topic: str):
    """
    Write raw parsed events to Parquet files.
    Partitioned by date for efficient historical queries.
    """
    count = batch_df.count()
    if count == 0:
        return

    output_path = f"{PARQUET_BASE}/{topic}"

    print(f"[PARQUET] Writing {count} {topic} events (batch {batch_id})")

    try:
        (
            batch_df
            .withColumn(
                "date",
                batch_df["timestamp"].cast("date").cast("string")
            )
            .write
            .mode("append")
            .partitionBy("date")
            .parquet(output_path)
        )
        print(f"[PARQUET] Written to {output_path}")
    except Exception as e:
        print(f"[PARQUET] Error writing {topic} parquet: {e}")
        raise