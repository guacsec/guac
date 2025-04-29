FROM arigaio/atlas:latest-alpine@sha256:8213d08e1859e0cfdb97a0fdf245cc72bb60e7cad05f562eb5a835ee313077ee

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
