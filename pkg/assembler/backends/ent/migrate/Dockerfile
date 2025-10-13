FROM arigaio/atlas:latest-alpine@sha256:42a386309c8f226561ef446419bf70344765cae6583929ebdc8dcf7ce6a73c06

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
