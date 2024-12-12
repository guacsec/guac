FROM arigaio/atlas:latest-alpine@sha256:7a2cd6af30690886def2c14637eaae89ce4a051249d940ad7e7e6071575ee520

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
