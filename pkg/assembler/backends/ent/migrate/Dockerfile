FROM arigaio/atlas:latest-alpine@sha256:ea497ba022b1b423292c4ca3df73876507b88a0f7edd7952f0499f99f5cda71c

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
