FROM python:3.11-slim

# Run as non-root user
RUN groupadd -r sentinel && useradd -r -g sentinel sentinel

WORKDIR /app

# Install dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# Create data directory with correct permissions
RUN mkdir -p /data && chown sentinel:sentinel /data

USER sentinel

EXPOSE 5000

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Use gunicorn for production-style serving
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", \
     "--timeout", "60", "--log-level", "info", \
     "--preload", "app:create_app()"]
