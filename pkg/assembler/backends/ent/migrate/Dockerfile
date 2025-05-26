FROM arigaio/atlas:latest-alpine@sha256:99a004bd11e8e52165318f76bded53fccfecd738b81d79f7bc2ba83924184289

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
