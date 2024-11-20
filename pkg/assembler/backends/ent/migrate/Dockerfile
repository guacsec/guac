FROM arigaio/atlas:latest-alpine@sha256:eaa219c96c06fabb9cccd0fed6db472ddfc53769c72f2e983d7df466a9157e72

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
