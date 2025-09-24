FROM arigaio/atlas:latest-alpine@sha256:3cb12049cb9d9e64931a665846a1e65ee5b8e16862b9c79ee92b428e3a7bb3a3

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
