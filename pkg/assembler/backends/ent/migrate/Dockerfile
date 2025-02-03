FROM arigaio/atlas:latest-alpine@sha256:c6eabfb07d06cd8cc78ece034500638093cc1168ffe3d7a77abdb65d7ba4507b

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
