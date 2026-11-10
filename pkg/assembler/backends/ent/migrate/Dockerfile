FROM arigaio/atlas:latest-alpine@sha256:7d411efb2322ba96c244fd86187007326d6e9b55ce7b8833d150f9880666cb97

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
