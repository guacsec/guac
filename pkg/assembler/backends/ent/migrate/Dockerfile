FROM arigaio/atlas:latest-alpine@sha256:9c1804dc0492d9401cfffa3e54125fb9695839aea2cd65b6f6ae7f981c3e0135

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
