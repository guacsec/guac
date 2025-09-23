FROM arigaio/atlas:latest-alpine@sha256:58bc1dd602b38013d99c4ae86e0169e676329686614ba9dc3562bfa73ab5ef7e

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
