FROM arigaio/atlas:latest-alpine@sha256:42457e3a68071c7433a63bf3880011c59ad4d0c3d5c56376be49419844b5bad1

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
