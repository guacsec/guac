FROM arigaio/atlas:latest-alpine@sha256:73374c58269118ff7617ba92590a98a55a859f6ca930ec71d51690cbf8e476ee

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
