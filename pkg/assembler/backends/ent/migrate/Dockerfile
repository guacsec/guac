FROM arigaio/atlas:latest-alpine@sha256:14f48edcba8f51beafc0f7ab9803cff0f810c5698399e6439902fbe833f13ab3

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
