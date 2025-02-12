FROM arigaio/atlas:latest-alpine@sha256:f10aa9be8ecba1abaab7298a94efcba6f3f36c9774ac3ecea3c98014e6b8880b

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
