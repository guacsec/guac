FROM arigaio/atlas:latest-alpine@sha256:3dec0f980d6252a90059943211748ba995d415c75e7fa59cf56261de699b2581

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
