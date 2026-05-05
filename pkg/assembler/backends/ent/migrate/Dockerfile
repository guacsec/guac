FROM arigaio/atlas:latest-alpine@sha256:69b0beecae45dd5c7bc662d85f7aa6ba62a95f8a4b5aa20c1195ef4f046ec105

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
