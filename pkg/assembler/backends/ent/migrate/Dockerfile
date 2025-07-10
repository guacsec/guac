FROM arigaio/atlas:latest-alpine@sha256:bd6b9820ce578b02d844d3eda993e2a5de5c0f72cd1d34aa6b4b1437dad8fdeb

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
