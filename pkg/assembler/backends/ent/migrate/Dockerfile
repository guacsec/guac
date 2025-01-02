FROM arigaio/atlas:latest-alpine@sha256:c976499771df4c01be22da9deacdf55582590b7e806e952c356a9f48d15e628f

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
