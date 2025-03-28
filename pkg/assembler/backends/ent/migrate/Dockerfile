FROM arigaio/atlas:latest-alpine@sha256:4fd5c04834e50704ec200b1f02a11bc41cf925e2b15e61be9b131481fc91f84c

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
