FROM arigaio/atlas:latest-alpine@sha256:0fd7b499030134fad97fb5868ef90d9bbaac7a1e187b7ded7ac79ec55689bc60

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
