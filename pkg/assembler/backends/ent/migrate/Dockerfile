FROM arigaio/atlas:latest-alpine@sha256:5ac6d4a0ba61333817ad3175ae3bb99aae44e4dc170c4d07512ed995ae96b8d2

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
