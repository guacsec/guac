FROM arigaio/atlas:latest-alpine@sha256:013d18b09f01656507b651a713a96f1f8e99a3000c3b503cd6aee5b6db1302c8

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
