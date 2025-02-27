FROM arigaio/atlas:latest-alpine@sha256:228f90cf867afe6b856429c45be512acc60ad0a473247a43720e049dfb538cc3

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
