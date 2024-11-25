FROM arigaio/atlas:latest-alpine@sha256:42953120a8ff89339c491d86aa84d2a3b6de73a4c5e767eb01091438c0144442

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
