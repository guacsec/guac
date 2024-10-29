FROM arigaio/atlas:latest-alpine@sha256:7a5338b039530425b38b5f1ef0e652273e67c0cef727f1793f2b1e36ff6242b4

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
