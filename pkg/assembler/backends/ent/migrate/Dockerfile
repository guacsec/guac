FROM arigaio/atlas:latest-alpine@sha256:a4d53233c5063599f6c2986d05e4eadd0f0cf718176e29275ade690b9399bbe0

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
