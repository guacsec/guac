FROM arigaio/atlas:latest-alpine@sha256:45dbda256179639427a44f332060750cf38428e3779da129625e41dee5678868

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
