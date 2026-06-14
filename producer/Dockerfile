FROM python:3.11-slim

WORKDIR /app

# Force Python to flush stdout immediately to Docker logs
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "producer.py"]