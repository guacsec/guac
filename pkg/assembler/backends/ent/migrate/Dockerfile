FROM arigaio/atlas:latest-alpine@sha256:e6b44616e09ee7da9f1aed692aa688f1794feea69316a734d3b665f0564e84de

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
