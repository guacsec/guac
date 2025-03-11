FROM arigaio/atlas:latest-alpine@sha256:a188af688891d6ac9a96c7d4460f4a84bd3833fd63f32cab586ad3227057373b

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
