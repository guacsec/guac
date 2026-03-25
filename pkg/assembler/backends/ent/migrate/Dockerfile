FROM arigaio/atlas:latest-alpine@sha256:7eec13901b820085af71d3eedbcf398e4f4d6e4dc3a32eb213e115501b18af1a

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
