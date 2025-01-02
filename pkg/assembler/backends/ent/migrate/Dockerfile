FROM arigaio/atlas:latest-alpine@sha256:67de5864c190931dc7cd0ffbefc8e5066e73687d29149f54faaa4f43e1dc0197

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
