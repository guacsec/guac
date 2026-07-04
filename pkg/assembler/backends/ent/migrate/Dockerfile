FROM arigaio/atlas:latest-alpine@sha256:c2fcd49538c3e7a2b145b78b0d8bffdb0897b2fde02b43914d6a8c52a4774baa

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
