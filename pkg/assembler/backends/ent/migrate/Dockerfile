FROM arigaio/atlas:latest-alpine@sha256:0389cdd8e6d4a393c134e09a10b52724bc42b8a3fc0e7fa62bf810eb9b8a2e2b

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
