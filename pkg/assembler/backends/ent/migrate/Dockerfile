FROM arigaio/atlas:latest-alpine@sha256:7181cab1113d38beb3c8d3b67426e467a0eb3e6adc2683a5ea53595f85a1789e

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
