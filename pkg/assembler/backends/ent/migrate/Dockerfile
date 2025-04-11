FROM arigaio/atlas:latest-alpine@sha256:0be07ddf3d87820ad0289186cc9cbe781abe06a55c957cc7601d3c70973e9044

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
