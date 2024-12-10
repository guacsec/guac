FROM arigaio/atlas:latest-alpine@sha256:07bc2560aef0ba5e300069b18dd6d7697fa045539d235a5521146ba3f1da236e

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
