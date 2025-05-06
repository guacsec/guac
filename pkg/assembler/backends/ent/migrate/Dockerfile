FROM arigaio/atlas:latest-alpine@sha256:08eaff040fa76919928a1dfe3a70a6e8127d8bdb64ffdd91c641661b79298a01

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
