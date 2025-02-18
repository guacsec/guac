FROM arigaio/atlas:latest-alpine@sha256:2c4a0b8b9f4207d96ae3d69f98964b346c1c810ce40d3ba1bf5f5c301e678d22

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
