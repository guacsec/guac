FROM arigaio/atlas:latest-alpine@sha256:3a7bbf7f6dad6209bf4289aea21602b663431cf2e3af95a986c0dec2d88e8a73

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
