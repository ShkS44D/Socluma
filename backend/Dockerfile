FROM python:3.12-slim

WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
RUN groupadd --gid 10001 socluma \
    && useradd --uid 10001 --gid socluma --home-dir /app socluma \
    && mkdir -p /var/lib/socluma/ioc-artifacts /var/lib/socluma/audit-exports /var/lib/socluma/audit-archives \
    && chown -R socluma:socluma /var/lib/socluma /app
COPY --chown=socluma:socluma . .

USER socluma

# Expose port
EXPOSE 8000

# Run migrations before starting the API server.
CMD ["sh", "-c", "alembic upgrade head && uvicorn src.main:app --host 0.0.0.0 --port 8000"]
