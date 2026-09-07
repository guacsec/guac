FROM arigaio/atlas:latest-alpine@sha256:eec0037e1490618058d018caa92e2cd23078c57909672d875de4c31462b7e8e6

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
