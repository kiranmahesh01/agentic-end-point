FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY packages/ packages/
COPY policies/ policies/
COPY services/pdp/ services/pdp/

RUN pip install --no-cache-dir -e .

EXPOSE 8082

CMD ["uvicorn", "services.pdp.app:app", "--host", "0.0.0.0", "--port", "8082"]
