FROM arigaio/atlas:latest-alpine@sha256:96753abb836489c6322e0e13c13f7e0a31dbbe3d8fbc0d2a4d5ef90eb2cf1512

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
