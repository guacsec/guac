FROM arigaio/atlas:latest-alpine@sha256:2e4743b17f3d4fff5b017b81e5b45863b8782fcb83ae1c8251f521e01fb0d75e

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
