FROM python:3.12-slim

WORKDIR /app

# Install Xvfb and ImageMagick (for screenshots)
# NOTE: We explicitly do NOT install any packages that could access the host display
RUN apt-get update && apt-get install -y --no-install-recommends \
    xvfb \
    imagemagick \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for safety
RUN useradd -m sandbox

# SAFETY: Ensure no access to host display
# Never set HOST_DISPLAY or DISPLAY to anything from the host
ENV DISPLAY=:99
ENV SANDBOX_DISPLAY=:99
ENV HOST_DISPLAY=""

COPY pyproject.toml .
COPY packages/ packages/
COPY services/isolated_desktop/ services/isolated_desktop/

RUN pip install --no-cache-dir -e .

# Run as non-root user
USER sandbox

EXPOSE 8089

CMD ["uvicorn", "services.isolated_desktop.app:app", "--host", "0.0.0.0", "--port", "8089"]
