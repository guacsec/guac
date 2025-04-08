FROM arigaio/atlas:latest-alpine@sha256:9d1a45cc4bdd10846fb727f035cb355d4618919394fe71ca84ed3cb60e87128a

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
