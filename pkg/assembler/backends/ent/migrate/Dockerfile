FROM arigaio/atlas:latest-alpine@sha256:00394cb61736735603cdcaf89c4be42b3b30af688f5256e6aa9ac2bcaf55c1e8

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
