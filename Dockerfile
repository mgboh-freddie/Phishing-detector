# 3.11 or newer is required: the model bundle is pickled with
# scikit-learn 1.8.0, which publishes no wheels for 3.10.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# curl is here for the HEALTHCHECK below -- it is not present in the
# slim base image.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY extract_features.py scan.py model_metrics.json ./
COPY phishing_html_model.joblib ./
COPY api/ ./api/

# The database directory is created and owned here, but a host bind
# mount over /app/data replaces this ownership with the host's own.
# SQLite runs in WAL mode and must create -wal/-shm files IN this
# directory, so mount a NAMED volume (which inherits the ownership
# set below) rather than a bind mount, or pre-chown the host directory
# to uid 1000. See docs/API.md, "Running it in Docker".
RUN useradd --create-home --uid 1000 appuser \
 && mkdir -p /app/data \
 && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD curl -fsS http://localhost:8000/v1/health || exit 1

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
