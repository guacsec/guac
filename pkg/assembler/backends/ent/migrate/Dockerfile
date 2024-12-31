FROM arigaio/atlas:latest-alpine@sha256:36e656850a5f6c674d996c96f91cad1278b4dc8770ddb1f9d0eebeb3dda8cd4a

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
