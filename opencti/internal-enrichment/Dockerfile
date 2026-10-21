FROM python:3.15-alpine@sha256:2699b90f4d562a22e2dd076c82f964032f64814204bff36d271a54ba4cc2c7e2 AS base
FROM base AS builder
RUN apk --no-cache add build-base libffi-dev libxml2-dev libxslt-dev
COPY internal-enrichment/requirements.lock /tmp/requirements.lock
RUN pip3 install --no-cache-dir --require-hashes --prefix=/install -r /tmp/requirements.lock

FROM base AS runtime
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apk --no-cache add 'zlib>=1.3.2-r1' libmagic libffi libxml2 libxslt libstdc++ \
    && python3 -m pip uninstall -y pip \
    && addgroup -g 10001 connector && adduser -D -u 10001 -G connector connector
COPY --from=builder /install /usr/local

# Copy the connector
COPY internal-enrichment/src /opt/connector
COPY common /opt/connector/common
WORKDIR /opt/connector

# Expose and entrypoint
COPY internal-enrichment/entrypoint.sh /
RUN chmod +x /entrypoint.sh
USER 10001:10001
ENTRYPOINT ["/entrypoint.sh"]
