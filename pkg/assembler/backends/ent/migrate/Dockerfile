FROM arigaio/atlas:latest-alpine@sha256:cdb29ba019d37846bc051c9278b4448b9a243655803cc729e8360425e286faad

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
