FROM arigaio/atlas:latest-alpine@sha256:a17b663f0d580271d1ee2fb7e093e027cdf72a3d040edf02a8d1d9852d1f38ae

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
