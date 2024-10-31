FROM arigaio/atlas:latest-alpine@sha256:c1cb4600890fe07fd21540028584d6cebd68c2021d327b626e531254986830d3

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
