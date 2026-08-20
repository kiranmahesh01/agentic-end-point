FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY README.md .
COPY LICENSE .
COPY packages/ packages/
COPY services/edr_sensor/ services/edr_sensor/

RUN pip install --no-cache-dir -e . docker

EXPOSE 8088

CMD ["uvicorn", "services.edr_sensor.app:app", "--host", "0.0.0.0", "--port", "8088"]
