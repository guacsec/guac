FROM arigaio/atlas:latest-alpine@sha256:4553d38b20145cb08000488f4e965d78e7bb0943a50e5f60ade4a1c2f8030b6c

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
