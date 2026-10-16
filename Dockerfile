# Assay — container image (UI + API + CLI). The audited code is mounted read-only; it is never executed.
FROM node:22.11-alpine AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12.7-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 10001 assay
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ backend/
COPY --from=web /web/dist frontend/dist
ENV ASSAY_HOST=0.0.0.0 ASSAY_PORT=3101 ASSAY_DATA_DIR=/data PYTHONUNBUFFERED=1
RUN mkdir -p /data && chown assay:assay /data
USER assay
WORKDIR /app/backend
EXPOSE 3101
HEALTHCHECK CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:3101/api/health', timeout=3).status==200 else 1)"
ENTRYPOINT ["python", "-m", "app.cli"]
CMD ["serve"]
