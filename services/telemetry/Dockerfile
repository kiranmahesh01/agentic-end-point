FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY README.md .
COPY LICENSE .
COPY packages/ packages/
COPY services/telemetry/ services/telemetry/

RUN pip install --no-cache-dir -e .

EXPOSE 8085

CMD ["uvicorn", "services.telemetry.app:app", "--host", "0.0.0.0", "--port", "8085"]
