FROM arigaio/atlas:latest-alpine@sha256:03d0ab9613df76f55df51d18782ddf04d65116a5a53b84c86fbb23fae5e0e069

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
