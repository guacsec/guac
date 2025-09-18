FROM arigaio/atlas:latest-alpine@sha256:e7a3a81ea1f15fe04ab39d705da834e0f85706dddcd49d36df4861488c53651e

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
