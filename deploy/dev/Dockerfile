FROM node:22-bookworm-slim AS node
FROM python:3.14.6-slim-bookworm

COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules/ /usr/local/lib/node_modules/
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx

# PG18 psql is required by the baseline dumps; Bookworm's default client is older.
# Install only Docker clients, never a daemon inside the development container.
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash ca-certificates curl git \
        build-essential libffi-dev libssl-dev libpq-dev pkg-config \
    && install -d -m 0755 /etc/apt/keyrings \
    && curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc -o /etc/apt/keyrings/postgresql.asc \
    && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
    && printf '%s\n' 'deb [signed-by=/etc/apt/keyrings/postgresql.asc] https://apt.postgresql.org/pub/repos/apt bookworm-pgdg main' > /etc/apt/sources.list.d/postgresql.list \
    && printf '%s\n' 'deb [signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable' > /etc/apt/sources.list.d/docker.list \
    && apt-get update && apt-get install -y --no-install-recommends \
        postgresql-client-18 docker-ce-cli docker-compose-plugin docker-buildx-plugin \
    && rm -rf /var/lib/apt/lists/*

RUN npm install --global --cache /tmp/npm-cache npm@11.16.0 \
    && rm -rf /tmp/npm-cache \
    && groupadd --gid 1000 dev \
    && useradd --uid 1000 --gid dev --create-home --shell /bin/bash dev \
    && mkdir -p /opt/venv /workspace/sli-platform/node_modules \
        /workspace/sli-platform/frontend/node_modules /home/dev/.npm \
    && chown -R dev:dev /opt/venv /workspace /home/dev

ENV HOME=/home/dev NPM_CONFIG_CACHE=/home/dev/.npm \
    PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    VIRTUAL_ENV=/opt/venv PATH="/opt/venv/bin:${PATH}"
COPY bootstrap.sh /usr/local/bin/sli-dev-bootstrap
USER dev
WORKDIR /workspace/sli-platform
ENTRYPOINT ["bash", "/usr/local/bin/sli-dev-bootstrap"]
CMD ["sleep", "infinity"]
