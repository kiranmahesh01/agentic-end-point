FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY packages/ packages/
COPY services/killswitch/ services/killswitch/

RUN pip install --no-cache-dir -e .

EXPOSE 8086

CMD ["uvicorn", "services.killswitch.app:app", "--host", "0.0.0.0", "--port", "8086"]
