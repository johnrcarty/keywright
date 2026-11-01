# Build from the repository root: docker build -f router/Dockerfile .
# The router carries no secrets: only its Keywright token, from the environment.
FROM python:3.13-slim@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb
ENV PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY third_party /usr/share/keywright/licenses
COPY scripts/release_materials.py /usr/share/keywright/release_materials.py
COPY deploy/runtime-constraints.txt /usr/share/keywright/runtime-constraints.txt
COPY LICENSE NOTICE THIRD_PARTY_NOTICES ./
LABEL org.opencontainers.image.licenses="Apache-2.0"
COPY client ./client
COPY router ./router
# The client from this tree, never from PyPI (acall landed with the router).
RUN pip install --no-cache-dir -c /usr/share/keywright/runtime-constraints.txt ./client ./router && keywright-router --help >/dev/null
RUN python /usr/share/keywright/release_materials.py inventory > /usr/share/keywright/dependency-inventory.json
RUN useradd --system --home /data router && mkdir -p /data && chown router /data
USER router
ENV ROUTER_STATE=/data/router.db
VOLUME /data
CMD ["keywright-router", "run", "--config", "/config/rules.yaml"]
