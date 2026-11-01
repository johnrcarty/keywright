FROM python:3.13-slim@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb
ENV PIP_NO_CACHE_DIR=1
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client curl git && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY third_party /usr/share/keywright/licenses
COPY scripts/release_materials.py /usr/share/keywright/release_materials.py
COPY deploy/runtime-constraints.txt /usr/share/keywright/runtime-constraints.txt
COPY pyproject.toml README.md LICENSE NOTICE THIRD_PARTY_NOTICES ./
COPY client ./client
COPY keywright_server ./keywright_server
# Both packages from this tree; the server must never resolve the client from PyPI here.
ARG KEYWRIGHT_EXTRAS="knowledge"
RUN pip install --no-cache-dir -c /usr/share/keywright/runtime-constraints.txt ./client ".${KEYWRIGHT_EXTRAS:+[$KEYWRIGHT_EXTRAS]}" && kw version && keywright-server --help >/dev/null
RUN python /usr/share/keywright/release_materials.py inventory > /usr/share/keywright/dependency-inventory.json
LABEL org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/johnrcarty/keywright" \
      org.opencontainers.image.description="Self-hosted SSH and MCP credential broker for AI agents"
ENV KW_DATA_DIR=/data KW_PORT=8700
VOLUME /data
EXPOSE 8700
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD curl -sf http://localhost:8700/healthz || exit 1
CMD ["keywright-server", "serve"]
