FROM arigaio/atlas:latest-alpine@sha256:12fa988c44390eaf4e57ff2abdadd35155724f59ab547127443a251a26fba308

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
