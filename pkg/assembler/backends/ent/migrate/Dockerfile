FROM arigaio/atlas:latest-alpine@sha256:14a5cf60b98dcad4bdc9bb5ce2b6ae9d6a785efd2954822c29012eb4d0d23600

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
