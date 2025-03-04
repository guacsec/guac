FROM arigaio/atlas:latest-alpine@sha256:8da354a2a18b28b7268e18e136f257691fa630d18be2168f365b227097d58408

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
