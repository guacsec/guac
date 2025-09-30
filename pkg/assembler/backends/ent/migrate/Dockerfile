FROM arigaio/atlas:latest-alpine@sha256:31c3d6ab951da0d135d1d3f405be0a89b8a75e8a88e454f3f1d598940925ee89

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
