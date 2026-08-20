FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY packages/ packages/
COPY services/registry/ services/registry/

RUN pip install --no-cache-dir -e .

EXPOSE 8081

CMD ["uvicorn", "services.registry.app:app", "--host", "0.0.0.0", "--port", "8081"]
