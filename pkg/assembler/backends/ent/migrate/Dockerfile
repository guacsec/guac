FROM arigaio/atlas:latest-alpine@sha256:e08b3fa87aa128325f5ba39dc26f19a6394b4a68d7c39ef15d36d71845fbdf8c

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
