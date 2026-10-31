# Build from the repository root: docker build -f router/Dockerfile .
# The router carries no secrets: only its Keywright token, from the environment.
FROM python:3.13-slim
WORKDIR /app
COPY client ./client
COPY router ./router
# The client from this tree, never from PyPI (acall landed with the router).
RUN pip install --no-cache-dir ./client ./router && keywright-router --help >/dev/null
RUN useradd --system --home /data router && mkdir -p /data && chown router /data
USER router
ENV ROUTER_STATE=/data/router.db
VOLUME /data
CMD ["keywright-router", "run", "--config", "/config/rules.yaml"]
