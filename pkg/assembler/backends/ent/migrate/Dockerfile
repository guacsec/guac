FROM arigaio/atlas:latest-alpine@sha256:eb123178a321693186794bae621b4834803a6066c754d52497b5f41dd71cf60a

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
