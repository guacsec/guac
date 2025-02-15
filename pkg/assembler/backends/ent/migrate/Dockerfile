FROM arigaio/atlas:latest-alpine@sha256:769a41c325e1ef66f2ca01e7aa5f24cf8d60d5fe88a9d9e0839455fe6448eae0

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
