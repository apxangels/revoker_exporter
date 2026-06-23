FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY exporter.py .
COPY revoker.yaml .

EXPOSE 9969

# Single worker + threads: all state is in-process; multiple workers
# would create separate caches and duplicate background checkers.
CMD ["gunicorn", "--bind", "0.0.0.0:9969", "--workers", "1", "--threads", "4", "--timeout", "30", "exporter:app"]
