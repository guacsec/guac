FROM arigaio/atlas:latest-alpine@sha256:9b622838d9e6146322bf3bd5a1f3882f71cbbba895954012d26b87840391d2c2

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
