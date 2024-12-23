FROM arigaio/atlas:latest-alpine@sha256:662c338178bbf8b772bbc4b26eb51ae638404577338483ff0bb8d0572da4e5ad

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
