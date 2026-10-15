FROM python:3.14-alpine@sha256:f6a589d43c42b9e7f7dc67a12d37132491f362859a5d750607710cc56da3bc72 AS base
FROM base AS builder
RUN apk --no-cache add build-base libffi-dev libxml2-dev libxslt-dev
COPY external-import/requirements.lock /tmp/requirements.lock
RUN pip3 install --no-cache-dir --require-hashes --prefix=/install -r /tmp/requirements.lock

FROM base AS runtime
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apk --no-cache add 'zlib>=1.3.2-r1' libmagic libffi libxml2 libxslt libstdc++ \
    && python3 -m pip uninstall -y pip \
    && addgroup -g 10001 connector && adduser -D -u 10001 -G connector connector
COPY --from=builder /install /usr/local

# Copy the connector
COPY external-import/src /opt/connector
COPY common /opt/connector/common
WORKDIR /opt/connector

# Expose and entrypoint
COPY external-import/entrypoint.sh /
RUN chmod +x /entrypoint.sh
USER 10001:10001
ENTRYPOINT ["/entrypoint.sh"]
