FROM arigaio/atlas:latest-alpine@sha256:1a72a21522764113019c83a4b9713cea20d814f14ca9d6044e7329135e8a5abe

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Create non-root user and switch to it
RUN addgroup -g 1001 -S appgroup && adduser -u 1001 -S appuser -G appgroup
USER appuser

ENTRYPOINT ["/app/entrypoint.sh"]
