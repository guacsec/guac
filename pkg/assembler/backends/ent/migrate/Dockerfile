FROM arigaio/atlas:latest-alpine@sha256:3ba899580eac0fd3ba0dfe00f92a542b70a03b14519afb8abc6aca78c7d722ea

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
