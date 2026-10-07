FROM node:24-bookworm-slim AS frontend
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --userconfig /dev/null --registry https://registry.npmjs.org
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim-trixie
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends postgresql-client openjdk-21-jre-headless ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 agentsec && useradd --uid 10001 --gid 10001 --no-create-home agentsec
COPY requirements.lock pyproject.toml alembic.ini ./
RUN pip install --index-url https://pypi.org/simple --no-cache-dir -r requirements.lock
COPY backend/ ./backend/
RUN pip install --index-url https://pypi.org/simple --no-deps -e .
COPY --from=frontend /build/dist ./frontend/dist
COPY --chmod=755 deploy/init.sh ./deploy/init.sh
RUN mkdir -p /app/data && chown -R 10001:10001 /app/data
USER 10001:10001
EXPOSE 8088
ENTRYPOINT ["agentsec"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8088"]
