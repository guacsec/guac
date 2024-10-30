FROM arigaio/atlas:latest-alpine@sha256:9ff9cbde13ce43e561a72defa0cd4ba8d8e6a8fb727f5e960cda4b73f7d5aa24

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
