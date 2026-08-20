FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY README.md .
COPY LICENSE .
COPY packages/ packages/
COPY services/approval/ services/approval/

RUN pip install --no-cache-dir -e .

EXPOSE 8084

CMD ["uvicorn", "services.approval.app:app", "--host", "0.0.0.0", "--port", "8084"]
