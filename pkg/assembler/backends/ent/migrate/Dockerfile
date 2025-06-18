FROM arigaio/atlas:latest-alpine@sha256:ed09dac5a1376cc147c701e8564bb9645f86d8871d5b6768af6c15f1c164056e

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
