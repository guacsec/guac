FROM arigaio/atlas:latest-alpine@sha256:e76e112e5d30195786bbf454476b88f97b4a392766a6d6b2a12067cbf712eb34

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
