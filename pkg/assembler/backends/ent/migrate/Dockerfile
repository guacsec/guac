FROM arigaio/atlas:latest-alpine@sha256:932129a8b44f28dc1cc30d88b26a567e8ff0e6a2677d02b231bc0c9012085077

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
