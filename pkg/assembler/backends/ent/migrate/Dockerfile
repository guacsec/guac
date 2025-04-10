FROM arigaio/atlas:latest-alpine@sha256:8a5b951890753300fd43f01061ba1d1f0271050f69961ecb1395ee30a071a529

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
