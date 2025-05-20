FROM arigaio/atlas:latest-alpine@sha256:64ec1a4a7571f9bc429894ee456fab61ede5fce639b784db89c674479de749f7

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
