FROM arigaio/atlas:latest-alpine@sha256:85cc1af09b0b3a680a9dd1a77c17f85b0a351adefffcecf82c60bfa6ae9c8cf3

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
