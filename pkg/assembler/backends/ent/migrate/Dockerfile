FROM arigaio/atlas:latest-alpine@sha256:dc5e2dc515319ea6f225e3afb06d76758bc3a4a3fb8c5ab211f5c1b9432dbccb

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
