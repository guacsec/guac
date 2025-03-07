FROM arigaio/atlas:latest-alpine@sha256:09c2b6e2cb33210585cc4a7be5be231e843c0acec4661d6444d41c62377497b8

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
