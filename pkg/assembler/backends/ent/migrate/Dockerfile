FROM arigaio/atlas:latest-alpine@sha256:855a3d7df1ec0d100ccb75a7643fef70cdae1bea8db0ddfb1cbd0dd87298d301

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
