FROM node:22-bookworm-slim AS frontend-build

WORKDIR /opt/sli
RUN apt-get update && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json ./
RUN npm ci
COPY frontend/package.json frontend/package-lock.json frontend/
RUN npm --prefix frontend ci
COPY frontend/ frontend/
COPY scripts/maintenance/publish_react_build.py scripts/maintenance/publish_react_build.py
# The frontend imports the navigation registry declared in config/ (stage 2).
COPY config/navigation_v3.json config/navigation_v3.json
COPY config/i18n/ config/i18n/
# The publisher backs up the existing bundle before replacing it with verified assets.
# Copy into the same layer as the publisher: overlayfs refuses to rename
# directories that live in a lower image layer (EXDEV).
COPY web/app/ /tmp/web-app/
RUN mkdir -p web/app && cp -a /tmp/web-app/. web/app/ && rm -rf /tmp/web-app \
    && npm --prefix frontend run build \
    && python3 scripts/maintenance/publish_react_build.py \
        --source artifacts/frontend/react-build --apply --confirm PUBLISH-REACT-BUILD

FROM python:3.14.6-slim-bookworm

ARG SLI_VERSION=0.0.0
LABEL org.opencontainers.image.version=$SLI_VERSION

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 ADLOG_DATA_DIR=/var/lib/sli
WORKDIR /opt/sli
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && mkdir -p /usr/share/postgresql-common/pgdg \
    && curl --fail --silent --show-error https://www.postgresql.org/media/keys/ACCC4CF8.asc \
       -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc \
    && echo 'deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt bookworm-pgdg main' > /etc/apt/sources.list.d/pgdg.list \
    && mkdir -p /etc/postgresql-common \
    && echo 'create_main_cluster = false' > /etc/postgresql-common/createcluster.conf \
    && apt-get update && apt-get install -y --no-install-recommends postgresql-client-18 util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 sli && useradd --uid 10001 --gid sli --no-create-home sli \
    && mkdir -p /var/lib/sli && chown sli:sli /var/lib/sli
# The restore-check sandbox needs initdb/pg_ctl/postgres. A separate layer keeps each
# layer below the update-package limit (128 MiB) enforced by the installed updater.
RUN apt-get update && apt-get install -y --no-install-recommends postgresql-18 \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.lock.txt ./
RUN pip install --no-cache-dir -r requirements.lock.txt
COPY server/ server/
COPY sli_collect/ sli_collect/
COPY sli_agent/ sli_agent/
COPY scripts/run_server.py scripts/run_server.py
COPY scripts/runtime/ scripts/runtime/
COPY scripts/auth/ scripts/auth/
COPY scripts/import/ scripts/import/
COPY scripts/maintenance/existing_postgres_bootstrap.py scripts/maintenance/existing_postgres_bootstrap.py
COPY scripts/maintenance/bundle_common.py scripts/maintenance/bundle_common.py
COPY config/ config/
COPY --from=frontend-build /opt/sli/web/app/ web/app/
COPY deploy/linux/ deploy/linux/
RUN sed 's/\r$//' deploy/linux/sli-secrets > /usr/local/bin/sli-secrets && chmod 0755 /usr/local/bin/sli-secrets
USER sli
ENTRYPOINT ["python", "-m", "deploy.linux.entrypoint"]
CMD ["api"]
