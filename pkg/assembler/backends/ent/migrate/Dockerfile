FROM arigaio/atlas:latest-alpine@sha256:e42d0ba5cb2476af482a4c5081668bef1d0c9b9bb4213c9a09bd1a259c255be5

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
