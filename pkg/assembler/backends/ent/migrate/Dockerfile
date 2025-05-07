FROM arigaio/atlas:latest-alpine@sha256:adb2b480dcd19930ec7d67c6c5602e032cac939bb0dd56e6084b298cb8733eb8

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
