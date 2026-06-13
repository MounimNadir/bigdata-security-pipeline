
FROM bitnami/spark:3.5.0

# Switch to root to install packages
USER root

# Install Python dependencies
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# ============================================================
# Download required JAR files
# These enable Spark to talk to Kafka and PostgreSQL
# ============================================================

# Directory where Spark looks for extra JARs
ENV SPARK_JARS_DIR=/opt/bitnami/spark/jars

# Kafka connector for Spark Structured Streaming
# Must match your Spark version (3.5) and Scala version (2.12)
RUN curl -o ${SPARK_JARS_DIR}/spark-sql-kafka.jar \
    https://repo1.maven.org/maven2/org/apache/spark/\
    spark-sql-kafka-0-10_2.12/3.5.0/\
    spark-sql-kafka-0-10_2.12-3.5.0.jar

# Kafka clients JAR (required by the Kafka connector)
RUN curl -o ${SPARK_JARS_DIR}/kafka-clients.jar \
    https://repo1.maven.org/maven2/org/apache/kafka/\
    kafka-clients/3.7.0/kafka-clients-3.7.0.jar

# Spark Kafka token provider (required dependency)
RUN curl -o ${SPARK_JARS_DIR}/spark-token-provider.jar \
    https://repo1.maven.org/maven2/org/apache/spark/\
    spark-token-provider-kafka-0-10_2.12/3.5.0/\
    spark-token-provider-kafka-0-10_2.12-3.5.0.jar

# Commons pool (required dependency for Kafka connector)
RUN curl -o ${SPARK_JARS_DIR}/commons-pool2.jar \
    https://repo1.maven.org/maven2/org/apache/commons/\
    commons-pool2/2.11.1/commons-pool2-2.11.1.jar

# PostgreSQL JDBC driver
RUN curl -o ${SPARK_JARS_DIR}/postgresql-jdbc.jar \
    https://repo1.maven.org/maven2/org/postgresql/\
    postgresql/42.7.1/postgresql-42.7.1.jar

# Set working directory
WORKDIR /app

# Copy all Spark source code
COPY . .

# Switch back to non-root user for security
USER 1001

# Run the Spark streaming job
CMD ["sh", "-c", "spark-submit \
    --master ${SPARK_MASTER} \
    --driver-memory ${SPARK_DRIVER_MEMORY} \
    --executor-memory ${SPARK_EXECUTOR_MEMORY} \
    --conf spark.sql.shuffle.partitions=4 \
    --conf spark.streaming.stopGracefullyOnShutdown=true \
    stream_processor.py"]