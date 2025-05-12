FROM arigaio/atlas:latest-alpine@sha256:fccc10ecc861e19f0387ee18069387428cf2491fbc320c029323c7aa98a8020d

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
