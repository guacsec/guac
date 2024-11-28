FROM arigaio/atlas:latest-alpine@sha256:5c465fda22363ea580d19900bcd1f03b1f079691ebde0c113a556c0af641f46c

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
