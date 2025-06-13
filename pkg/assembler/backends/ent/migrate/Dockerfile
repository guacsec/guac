FROM arigaio/atlas:latest-alpine@sha256:736f572b1a9156af10eb5a14928746a67458c9e031956af3cb1ae8cd092cfd62

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
