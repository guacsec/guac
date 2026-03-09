FROM arigaio/atlas:latest-alpine@sha256:97322b013f25b6c9dd7a7f76c4263c4bc51a0dfb68ec634fd2f642779eeb3d51

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
