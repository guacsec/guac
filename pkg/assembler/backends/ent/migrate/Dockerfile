FROM arigaio/atlas:latest-alpine@sha256:a4cefc90b86eb6bcb0c88713c8f7505b7b03fc98ca57c018d04edb875286dd83

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
