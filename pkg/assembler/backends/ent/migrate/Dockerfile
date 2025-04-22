FROM arigaio/atlas:latest-alpine@sha256:2ad52caf5b9dc082534d4bd24b958b51a3f55233150771d4fb27b1e4d0c665ec

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
