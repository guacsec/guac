FROM arigaio/atlas:latest-alpine@sha256:55506f8ea01c36bcb56505eaa687d707a2f3fb2b58cdcb6cfaadaf6bf1928939

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
