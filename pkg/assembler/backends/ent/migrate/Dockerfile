FROM arigaio/atlas:latest-alpine@sha256:2711032417cb574f00d831af89f93b975d2db2ab8038fffb245db7d4317f6056

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
