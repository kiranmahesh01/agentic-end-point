FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY packages/ packages/
COPY services/egress_proxy/ services/egress_proxy/

RUN pip install --no-cache-dir -e .

EXPOSE 8087

CMD ["uvicorn", "services.egress_proxy.app:app", "--host", "0.0.0.0", "--port", "8087"]
