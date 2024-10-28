FROM arigaio/atlas:latest-alpine@sha256:54ac9c02f9ca6741fa35876f344da583bd9d2f75a2bf69a993a99627331494a0

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
