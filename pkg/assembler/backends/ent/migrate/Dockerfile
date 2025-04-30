FROM arigaio/atlas:latest-alpine@sha256:a16ba695a5659d8f2cd72c78b067ab816f35794c6807144d4d859da2fd8dcd10

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
