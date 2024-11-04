FROM arigaio/atlas:latest-alpine@sha256:a3b29b497c025fcee469ee0337512541ebd4f714dfe7498073a41f3327076593

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
