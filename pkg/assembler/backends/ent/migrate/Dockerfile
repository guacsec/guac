FROM arigaio/atlas:latest-alpine@sha256:9bb0a54d1bc6f6a96f202e64fde6439d564c6b21e0bcb1a4454216890daf8bff

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
