FROM arigaio/atlas:latest-alpine@sha256:7cf187cbd7c0d07ff9d6083cdf0726a2e9ff37b60cab0412bb09e55aa4c0663e

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
