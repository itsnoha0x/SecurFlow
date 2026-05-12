FROM python:3.11-slim

RUN apt-get update && apt-get install -y wget curl \
    && wget https://github.com/aquasecurity/trivy/releases/download/v0.49.0/trivy_0.49.0_Linux-64bit.deb \
    && dpkg -i trivy_0.49.0_Linux-64bit.deb \
    && rm trivy_0.49.0_Linux-64bit.deb

RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY src/ /opt/securflow/src/
RUN mkdir -p /opt/securflow/shared

COPY docker/docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

WORKDIR /opt/securflow
ENTRYPOINT ["docker-entrypoint.sh"]
