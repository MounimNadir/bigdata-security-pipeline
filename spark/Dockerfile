FROM python:3.11-slim

# Set working directory inside container
WORKDIR /app

# Copy and install dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all producer source code
COPY . .

# Run the producer
CMD ["python", "producer.py"]