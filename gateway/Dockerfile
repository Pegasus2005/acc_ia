FROM python:3.11-slim

# Run as non-root user
RUN groupadd -r sentinel && useradd -r -g sentinel sentinel

WORKDIR /app

# Install dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# Create /data and ensure /tmp is writable by sentinel (for SQLite on free tier)
RUN mkdir -p /data && chown sentinel:sentinel /data && \
    chmod 1777 /tmp

USER sentinel

EXPOSE 5000

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV DB_PATH=/tmp/sentinelshield.db

# gunicorn supports app:create_app() factory natively — each worker calls it
# independently. Do NOT use --preload with a factory + SQLite (fork-safety issue).
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", \
     "--timeout", "60", "--log-level", "info", \
     "app:create_app()"]

