FROM arigaio/atlas:latest-alpine@sha256:f1719553ebd3318fc4904135178e202dad054403e9a1ba12cddfd4d4b0c98a20

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
