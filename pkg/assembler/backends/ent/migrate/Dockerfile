FROM arigaio/atlas:latest-alpine@sha256:ab7d79f48126e043930756c46faa8e15fdc65cfa1c84caad0cad1c5b78b6cf7c

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
