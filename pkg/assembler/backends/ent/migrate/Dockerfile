FROM arigaio/atlas:latest-alpine@sha256:a28fb881d6bc7e4291cd1fa3e6c0ae6ec64aaa29e63587d76cafea67d6097c95

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
