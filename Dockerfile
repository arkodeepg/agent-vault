FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    S_VAULT_PATH=/data/vault.senv \
    PYTHONPATH=/app

WORKDIR /app
COPY docker/vendor /usr/local/lib/python3.12/site-packages
COPY agent_vault ./agent_vault
COPY bin/s /usr/local/bin/s
RUN chmod +x /usr/local/bin/s && mkdir -p /data

VOLUME ["/data"]
ENTRYPOINT ["s"]
CMD ["help"]
