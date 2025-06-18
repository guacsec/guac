FROM arigaio/atlas:latest-alpine@sha256:7f5d8a7ee8df732d61aa74b5f237e6c0ad67126f497e82470156f1f1ef618f7b

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
