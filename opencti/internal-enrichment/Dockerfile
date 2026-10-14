FROM python:3.13-alpine
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

# Install Python modules
RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev
COPY internal-enrichment/requirements.lock /tmp/requirements.lock
RUN pip3 install --no-cache-dir -r /tmp/requirements.lock

# Copy the connector
COPY internal-enrichment/src /opt/connector
COPY common /opt/connector/common
WORKDIR /opt/connector

# Expose and entrypoint
COPY internal-enrichment/entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
