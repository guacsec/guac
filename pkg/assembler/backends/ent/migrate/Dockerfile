FROM arigaio/atlas:latest-alpine@sha256:dc615a239b410801413bd25eef6f86b43fcb4ca89c7db0c279f8ec4df5d4e28e

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
