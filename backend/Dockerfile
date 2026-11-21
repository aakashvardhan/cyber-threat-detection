# Threat Console backend (FastAPI). Build from the repository root:
#   docker build -f backend/Dockerfile -t threat-console-backend .
# Model checkpoints, test data and knowledge files are not in the image: mount them at /app/backend/data
# (docker compose does this) or sync them from S3 on AWS.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HF_HOME=/opt/hf

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app/backend

# CPU-only PyTorch first (much smaller than the CUDA build), then the rest
COPY backend/requirements.txt .
RUN pip install --index-url https://download.pytorch.org/whl/cpu torch \
    && pip install -r requirements.txt

# Embedding model baked into the image, so the container starts without downloading it
ARG EMBED_MODEL=sentence-transformers/all-MiniLM-L6-v2
RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('${EMBED_MODEL}')"
# Reranker (RERANK_MODEL in the backend environment must match; RERANK=false turns it off)
ARG RERANK_MODEL=cross-encoder/ms-marco-MiniLM-L-6-v2
RUN python -c "from sentence_transformers import CrossEncoder; CrossEncoder('${RERANK_MODEL}')"

COPY backend/ .

# Run as a non-root user
RUN useradd --create-home --uid 1000 app && chown -R app /app
USER app

EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --start-period=120s --retries=5 \
    CMD curl -fs http://localhost:8000/health || exit 1
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
