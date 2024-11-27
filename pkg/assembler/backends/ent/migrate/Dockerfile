FROM arigaio/atlas:latest-alpine@sha256:d448aabf4fa19de45d13df44db2346901127ac9f8e341d88ed6d442279508a6c

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
