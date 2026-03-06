FROM arigaio/atlas:latest-alpine@sha256:9acdd1ea3d0a456fd2b3c75876d1c331eb1b4293d52e9ed9df0ea076ca730367

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
