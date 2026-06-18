FROM arigaio/atlas:latest-alpine@sha256:ebe9927a3f5f2c33540f000a5fe2143bd751b0bb5ecf9d14d6d989155cc097e8

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
