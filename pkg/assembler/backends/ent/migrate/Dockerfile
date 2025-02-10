FROM arigaio/atlas:latest-alpine@sha256:9df7d17cad94eacf149c5fbcd60be0d4a4b1780ce5683d9b304ebe6f6528a59c

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
