FROM arigaio/atlas:latest-alpine@sha256:b3cc7fa83eaa8aca8d591ec273dbf7d78639f8357eb24fdcde862b5b78beb2d2

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
