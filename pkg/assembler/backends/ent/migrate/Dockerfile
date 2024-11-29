FROM arigaio/atlas:latest-alpine@sha256:a0d43a6c706aaf489c90255348222a285259c37b0935f738d48c895ac770b4be

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
