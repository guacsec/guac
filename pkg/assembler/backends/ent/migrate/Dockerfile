FROM arigaio/atlas:latest-alpine@sha256:df235a5febc2dad950798affc64e2701436f840f73d03c08abd294d0db2e3e3c

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
