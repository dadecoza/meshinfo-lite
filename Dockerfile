# trunk-ignore-all(checkov/CKV_DOCKER_3)
FROM python:3.13.3-slim-bookworm

LABEL org.opencontainers.image.source=https://github.com/agessaman/meshinfo-lite
LABEL org.opencontainers.image.description="Realtime web UI to run against a Meshtastic regional or private mesh network."

ENV MQTT_TLS=false
ENV PYTHONUNBUFFERED=1 \
    # Set standard locations
    PATH="/app/.local/bin:${PATH}" \
    # Consistent port for the app
    APP_PORT=8000 \
    # Optimize pip for faster builds
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd --system app && \
    useradd --system --gid app --home-dir /app --create-home app

# Set the working directory in the container
WORKDIR /app

# Install system dependencies
ARG TARGETPLATFORM
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libexpat1 \
    libcairo2 \
    pkg-config \
    fonts-symbola \
    fontconfig \
    freetype2-demos \
    libgdal-dev \
    gdal-bin \
    libgeos-dev \
    libproj-dev \
    proj-bin \
    default-mysql-client \
    $([ "$TARGETPLATFORM" = "linux/arm64" ] && echo "curl") \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN fc-cache -fv

# Architecture-specific rasterio installation
ENV GDAL_CONFIG=/usr/bin/gdal-config

# For ARM64: Install conda/mamba and use conda-forge for rasterio
RUN if [ "$TARGETPLATFORM" = "linux/arm64" ]; then \
    curl -L -O https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-Linux-aarch64.sh && \
    bash Miniforge3-Linux-aarch64.sh -b -p /opt/conda && \
    rm Miniforge3-Linux-aarch64.sh && \
    /opt/conda/bin/mamba install -c conda-forge rasterio -y; \
    fi

# Update PATH to include conda if installed
ENV PATH="/opt/conda/bin:${PATH}"

COPY requirements.txt banner run.sh ./

# Upgrade pip and install packages
RUN pip install --upgrade pip setuptools wheel

# Install requirements, excluding rasterio for ARM64 (already installed via conda)
RUN if [ "$TARGETPLATFORM" = "linux/arm64" ]; then \
    grep -v "^rasterio" requirements.txt > requirements_filtered.txt || echo "" > requirements_filtered.txt; \
    else \
    cp requirements.txt requirements_filtered.txt; \
    fi

RUN su app -c "pip install --no-cache-dir --user -r requirements_filtered.txt"

COPY --chown=app:app banner run.sh ./
COPY --chown=app:app *.py ./
COPY --chown=app:app *.sh ./
COPY --chown=app:app www  ./www
COPY --chown=app:app templates ./templates
COPY --chown=app:app migrations ./migrations

HEALTHCHECK NONE

RUN chmod +x run.sh
RUN chmod +x *.sh

USER app

EXPOSE ${APP_PORT}

CMD ["./run.sh"]