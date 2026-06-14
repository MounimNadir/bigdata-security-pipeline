FROM apache/spark:3.5.0

# Switch to root to install packages
USER root

# Install Python dependencies
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# ============================================================
# Download required JAR files
# These enable Spark to talk to Kafka and PostgreSQL
# ============================================================

ENV SPARK_JARS_DIR=/opt/spark/jars

# Kafka connector for Spark Structured Streaming
RUN curl -o ${SPARK_JARS_DIR}/spark-sql-kafka.jar \
    https://repo1.maven.org/maven2/org/apache/spark/spark-sql-kafka-0-10_2.12/3.5.0/spark-sql-kafka-0-10_2.12-3.5.0.jar

# Kafka clients JAR
RUN curl -o ${SPARK_JARS_DIR}/kafka-clients.jar \
    https://repo1.maven.org/maven2/org/apache/kafka/kafka-clients/3.7.0/kafka-clients-3.7.0.jar

# Spark Kafka token provider
RUN curl -o ${SPARK_JARS_DIR}/spark-token-provider.jar \
    https://repo1.maven.org/maven2/org/apache/spark/spark-token-provider-kafka-0-10_2.12/3.5.0/spark-token-provider-kafka-0-10_2.12-3.5.0.jar

# Commons pool (required by Kafka connector)
RUN curl -o ${SPARK_JARS_DIR}/commons-pool2.jar \
    https://repo1.maven.org/maven2/org/apache/commons/commons-pool2/2.11.1/commons-pool2-2.11.1.jar

# PostgreSQL JDBC driver
RUN curl -o ${SPARK_JARS_DIR}/postgresql-jdbc.jar \
    https://repo1.maven.org/maven2/org/postgresql/postgresql/42.7.1/postgresql-42.7.1.jar

# ============================================================
# Set working directory and copy source code
# ============================================================
WORKDIR /app

COPY . .

# ============================================================
# Run the Spark streaming job
# ============================================================
CMD ["/opt/spark/bin/spark-submit", \
     "--master", "local[*]", \
     "--driver-memory", "2g", \
     "--executor-memory", "2g", \
     "--conf", "spark.sql.shuffle.partitions=4", \
     "--conf", "spark.streaming.stopGracefullyOnShutdown=true", \
     "--conf", "spark.ui.port=4040", \
     "stream_processor.py"]