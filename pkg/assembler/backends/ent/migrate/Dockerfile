FROM arigaio/atlas:latest-alpine@sha256:2b7ec6562eb8245417eca21d51831871dde7b82b2cb8d158bb11fcba1b598ffb

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
