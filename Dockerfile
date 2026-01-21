FROM python:3.11-slim-bookworm

ARG DEV_ENV

WORKDIR /src

COPY . /src
COPY ./docker/entrypoint.sh /entrypoint.sh
COPY ./docker/server.ini /docker_server.ini

RUN apt-get update && apt-get install -y curl ca-certificates --no-install-recommends python3-dev build-essential libgdk-pixbuf2.0-0 \
    libpq-dev libsasl2-dev libldap2-dev libssl-dev libmagic1 redis-tools netcat-traditional\
    && pip install -U pip --no-cache-dir \
    && rm -rf /var/lib/{apt,dpkg,cache,log}/ \
    && chmod +x /entrypoint.sh

# Install uv
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:$PATH"

# Build development environment if DEV_ENV is true:
# - Install package in editable mode (-e flag) to allow live code changes
# - Keep source code for development
# Otherwise for production:
# - Install package normally
# - Remove source code to reduce image size
RUN if [ ! -z "$DEV_ENV" ]; then \
    echo "Building dev environment ..." && \
    uv sync --frozen --no-cache; \
    else \
    uv sync --frozen --no-dev --no-cache --no-editable; \
    fi

# Add uv-installed dependencies to PATH
ENV PATH="/root/.local/bin:$PATH:/src/.venv/bin"

WORKDIR /home/faraday

RUN mkdir -p /home/faraday/.faraday/config
RUN mkdir -p /home/faraday/.faraday/logs
RUN mkdir -p /home/faraday/.faraday/session
RUN mkdir -p /home/faraday/.faraday/storage


ENV PYTHONUNBUFFERED=1
ENV FARADAY_HOME=/home/faraday
