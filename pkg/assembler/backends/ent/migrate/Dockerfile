FROM arigaio/atlas:latest-alpine@sha256:68db5344832402fb88b0df8bbebb8e7c54ffb8e89f41921c6282fdec400808bc

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
