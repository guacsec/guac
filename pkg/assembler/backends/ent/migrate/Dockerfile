FROM arigaio/atlas:latest-alpine@sha256:f67211565bb1fb35e872f4b4cceb7487d9faf439574622ce6d37c179ae28184f

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
