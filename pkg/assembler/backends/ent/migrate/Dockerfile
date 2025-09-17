FROM arigaio/atlas:latest-alpine@sha256:f152599d2d400581ce59194208fd199233e1c8bdaced0e98d2ee8b7deead6094

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
