FROM arigaio/atlas:latest-alpine@sha256:b190ff105611d5ca46febf47a2f4cdbb88ba059daf61c3f9caec41907c6ca465

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
