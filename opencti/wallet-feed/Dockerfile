FROM python:3.13-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT
RUN apk --no-cache add build-base libmagic libffi-dev libxml2-dev libxslt-dev
COPY internal-enrichment/requirements.lock /tmp/requirements.lock
RUN pip3 install --no-cache-dir -r /tmp/requirements.lock
COPY common /opt/connector/common
COPY wallet-feed/src /opt/connector
WORKDIR /opt/connector
COPY wallet-feed/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
