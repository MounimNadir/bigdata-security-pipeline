FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install dependencies first (Docker layer caching)
# If requirements.txt doesn't change, this layer is cached
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Run the producer
CMD ["python", "producer.py"]