FROM arigaio/atlas:latest-alpine@sha256:9e0d9f9a781c0ab7b0d5900e36e5f0ef72a92e3ff167671ad42ae3ba0458dca6

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
