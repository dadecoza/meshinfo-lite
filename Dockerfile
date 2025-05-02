# trunk-ignore-all(checkov/CKV_DOCKER_3)
FROM python:3.13.3-slim-bookworm

LABEL org.opencontainers.image.source=https://github.com/agessaman/meshinfo-lite
LABEL org.opencontainers.image.description="Realtime web UI to run against a Meshtastic regional or private mesh network."

ENV MQTT_TLS=false
ENV PYTHONUNBUFFERED=1 \
    # Set standard locations
    PATH="/app/.local/bin:${PATH}" \
    # Consistent port for the app
    APP_PORT=8000

RUN groupadd --system app && \
    useradd --system --gid app --home-dir /app --create-home app

# Set the working directory in the container
WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libexpat1 \
    libcairo2 \
    pkg-config \
    fonts-symbola \
    fontconfig \
    freetype2-demos \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN fc-cache -fv

COPY requirements.txt banner run.sh ./

RUN pip install --upgrade pip
RUN su app -c "pip install --no-cache-dir --user -r requirements.txt"

COPY --chown=app:app banner run.sh ./
COPY --chown=app:app *.py ./
COPY --chown=app:app www  ./www
COPY --chown=app:app templates ./templates
COPY --chown=app:app migrations ./migrations

HEALTHCHECK NONE

RUN chmod +x run.sh

USER app

EXPOSE ${APP_PORT}

CMD ["./run.sh"]
