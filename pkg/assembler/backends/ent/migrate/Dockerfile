FROM arigaio/atlas:latest-alpine@sha256:48b19f47603ffc8281a5e885523bda9fb4bd77260990696f7e7d22581f0d1c29

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
