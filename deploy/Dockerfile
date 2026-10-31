FROM python:3.13-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client curl git && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml README.md ./
COPY client ./client
COPY keywright_server ./keywright_server
# Both packages from this tree; the server must never resolve the client from PyPI here.
ARG KEYWRIGHT_EXTRAS=""
RUN pip install --no-cache-dir ./client ".${KEYWRIGHT_EXTRAS:+[$KEYWRIGHT_EXTRAS]}" && kw version && keywright-server --help >/dev/null
ENV KW_DATA_DIR=/data KW_PORT=8700
VOLUME /data
EXPOSE 8700
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD curl -sf http://localhost:8700/healthz || exit 1
CMD ["keywright-server", "serve"]
