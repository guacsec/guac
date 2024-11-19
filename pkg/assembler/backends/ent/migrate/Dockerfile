FROM arigaio/atlas:latest-alpine@sha256:0cabbd95de5b1879d268b63dec95982ddd9c960c911ca634a8b26a3485303c8d

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
