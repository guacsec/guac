FROM arigaio/atlas:latest-alpine@sha256:0c43c7c4b41722ad9b7c24ea4aae8212908024f59a4bd4fd46d22d0ec68ca8c5

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Create non-root user and switch to it
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

ENTRYPOINT ["/app/entrypoint.sh"]
