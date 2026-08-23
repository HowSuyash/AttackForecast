# Container for hosting the dashboard (Hugging Face Spaces, Render, Fly, or any
# Docker host).
#
# The image is self-contained because the repository ships the trained
# checkpoint (~560 KB) and the prepared state cells (~14 MB). Nothing downloads
# CTU-13 at build or run time - a 1.9 GB fetch inside a build step would be slow
# and fragile, and the raw captures are not needed once the parquet files exist.

FROM python:3.12-slim

# curl is only here for the healthcheck; no build toolchain is needed because
# every wheel we install is manylinux.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Torch first, from the CPU index. The default PyPI wheel drags in the CUDA
# runtime - roughly 2 GB of libraries this project never touches, since the
# model is 138k parameters and trains on CPU in minutes.
COPY requirements.txt .
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu \
    && pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY server/ ./server/
# Both checkpoints and reports: the dashboard's Benchmark tab serves
# artifacts/reports/benchmark.json, so copying only the checkpoint directory
# leaves that tab returning 404 in the container.
COPY artifacts/ ./artifacts/
COPY data/processed/ ./data/processed/

# Hugging Face Spaces expects 7860; Render and Fly inject $PORT. Defaulting to
# 7860 and honouring $PORT covers both without a platform-specific image.
ENV PORT=7860
EXPOSE 7860

# The first request to /api/hosts scores every host in a capture and is slow;
# the ranking is then memoised. Give the healthcheck room for that.
HEALTHCHECK --interval=30s --timeout=10s --start-period=90s --retries=3 \
    CMD curl -fsS "http://localhost:${PORT}/api/meta" || exit 1

CMD ["sh", "-c", "uvicorn server.app:app --host 0.0.0.0 --port ${PORT}"]
