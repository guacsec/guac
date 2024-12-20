FROM arigaio/atlas:latest-alpine@sha256:bb59a2422998e2d5484bea94773acfe893eefef006a652153dcd577a33714b8e

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
