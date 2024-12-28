FROM arigaio/atlas:latest-alpine@sha256:dd03f5b365d3c62cae9ff37ad7eb4a0d663183955e7240aa5490fac3246f26ec

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
