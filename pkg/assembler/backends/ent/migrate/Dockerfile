FROM arigaio/atlas:latest-alpine@sha256:a87216504ce28631b32b87b6dbcb4e099abb8b85a121201bcebd392444ed620d

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
