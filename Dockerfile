FROM python:3.12-slim

ARG AGENT_VAULT_VERSION=0.1.0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    S_VAULT_PATH=/data/vault.senv \
    AGENT_VAULT_VERSION=${AGENT_VAULT_VERSION} \
    PYTHONPATH=/app

LABEL org.opencontainers.image.title="Agent Vault" \
      org.opencontainers.image.description="Password manager for AI agents that use secrets without seeing raw values" \
      org.opencontainers.image.version="${AGENT_VAULT_VERSION}"

WORKDIR /app
COPY docker/vendor /usr/local/lib/python3.12/site-packages
COPY agent_vault ./agent_vault
COPY docs/AGENT_README.md ./docs/AGENT_README.md
COPY bin/s /usr/local/bin/s
RUN chmod +x /usr/local/bin/s && mkdir -p /data

VOLUME ["/data"]
ENTRYPOINT ["s"]
CMD ["help"]
