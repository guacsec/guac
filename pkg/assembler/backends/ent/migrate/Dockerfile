FROM arigaio/atlas:latest-alpine@sha256:74da46c441a5daa1f7b6c54e7eb556c4eec37f65b054f75e18ac5d5fa169b3ad

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
