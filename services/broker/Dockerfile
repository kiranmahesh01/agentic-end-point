FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY README.md .
COPY LICENSE .
COPY packages/ packages/
COPY services/broker/ services/broker/

RUN pip install --no-cache-dir -e .

EXPOSE 8080

CMD ["uvicorn", "services.broker.app:app", "--host", "0.0.0.0", "--port", "8080"]
