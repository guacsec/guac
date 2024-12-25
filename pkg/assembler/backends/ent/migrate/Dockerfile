FROM arigaio/atlas:latest-alpine@sha256:913917f0e1fe85ce7d3fa786debe5c1f214e90ac394faa511ca2b97b9ee7681e

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
