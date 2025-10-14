FROM arigaio/atlas:latest-alpine@sha256:70532456e33886e6809fba40ab607e57aea701419d39c7d76656aa263c3642f6

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
