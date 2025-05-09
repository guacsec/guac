FROM arigaio/atlas:latest-alpine@sha256:c2910f844a4f892696b67db7b193439f134bf6b819d4bc43a4480851fec17abe

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
