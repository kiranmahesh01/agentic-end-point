FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY README.md .
COPY LICENSE .
COPY packages/ packages/
COPY services/demo_agent/ services/demo_agent/

RUN pip install --no-cache-dir -e .

EXPOSE 8090

CMD ["uvicorn", "services.demo_agent.app:app", "--host", "0.0.0.0", "--port", "8090"]
