FROM arigaio/atlas:latest-alpine@sha256:6e2eef973c7ff7e716aae0c7e9a79825d1ca8054db900bdbcad09c528021e6a6

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
