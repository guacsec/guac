FROM arigaio/atlas:latest-alpine@sha256:062cd81fd3419725ebfd6b546f9760eb781f84574b9f9bbe17082ad98b1e5449

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
