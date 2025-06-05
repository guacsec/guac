FROM arigaio/atlas:latest-alpine@sha256:6faaa93d0b2933576d74b31b5bc2f653a346d0deb71cdcb340db3472a170ee44

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
