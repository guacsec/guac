FROM arigaio/atlas:latest-alpine@sha256:4a489be786d0c5779356bf13e4157a9da2f5a990a068add259a6dc4157e2184e

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
