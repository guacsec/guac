FROM arigaio/atlas:latest-alpine@sha256:8b7c2df4df81f3233813bf79e2588578e144358b7b9d4eabbe11774dd4aa7f92

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
