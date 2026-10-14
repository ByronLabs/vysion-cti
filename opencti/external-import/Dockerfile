FROM python:3.13-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Install Python modules
RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev
COPY requirements.lock /tmp/requirements.lock
RUN pip3 install --no-cache-dir -r /tmp/requirements.lock

# Copy the connector
COPY src /opt/connector
WORKDIR /opt/connector

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
