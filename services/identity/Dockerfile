FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY README.md .
COPY LICENSE .
COPY packages/ packages/
COPY services/identity/ services/identity/

RUN pip install --no-cache-dir -e .

EXPOSE 8083

CMD ["uvicorn", "services.identity.app:app", "--host", "0.0.0.0", "--port", "8083"]
