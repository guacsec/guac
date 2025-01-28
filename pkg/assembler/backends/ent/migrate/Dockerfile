FROM arigaio/atlas:latest-alpine@sha256:d571cbca2fd13635e75b7d6cee99f642eb05a68b077da2961d0faf67fe23ab26

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
