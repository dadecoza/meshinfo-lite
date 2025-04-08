# trunk-ignore-all(checkov/CKV_DOCKER_3)
FROM python:3.13-slim

LABEL org.opencontainers.image.source=https://github.com/dadecoza/meshinfo-lite
LABEL org.opencontainers.image.description="Realtime web UI to run against a Meshtastic regional or private mesh network."

ENV MQTT_TLS=false
ENV PYTHONUNBUFFERED=1

# Set the working directory in the container
RUN mkdir /app
WORKDIR /app

RUN apt-get update && apt-get -y install \
    libexpat1 libexpat1-dev

COPY requirements.txt banner run.sh ./
COPY *.py ./
COPY www  ./www
COPY templates ./templates
COPY migrations ./migrations

RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

HEALTHCHECK NONE

EXPOSE 8080

RUN chmod +x run.sh

CMD ["./run.sh"]
