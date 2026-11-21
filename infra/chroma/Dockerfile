# Chroma vector database server, same major/minor version as the backend's chromadb client.
FROM python:3.12-slim
ARG CHROMA_SPEC="chromadb>=1.5,<1.6"
RUN pip install --no-cache-dir "${CHROMA_SPEC}" \
    && apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
VOLUME /data
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --retries=12 CMD curl -fs http://localhost:8000/api/v2/heartbeat || exit 1
CMD ["chroma", "run", "--host", "0.0.0.0", "--port", "8000", "--path", "/data"]
