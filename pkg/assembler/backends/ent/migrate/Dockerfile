FROM arigaio/atlas:latest-alpine@sha256:b6f78d809e42171fe97410d76eaaf06c5a34d584bd1519cea7d1455adebdbdfe

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
