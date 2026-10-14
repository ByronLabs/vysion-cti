FROM python:3.13-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Install Python modules
RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev
COPY external-import/requirements.lock /tmp/requirements.lock
RUN pip3 install --no-cache-dir -r /tmp/requirements.lock

# Copy the connector
COPY external-import/src /opt/connector
COPY common /opt/connector/common
WORKDIR /opt/connector

# Expose and entrypoint
COPY external-import/entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
