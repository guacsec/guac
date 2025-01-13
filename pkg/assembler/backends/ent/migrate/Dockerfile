FROM arigaio/atlas:latest-alpine@sha256:a45b6bc3910de0150556d6493ab1fe21a7e1590f6dfee28a4b3cb6f87d788e27

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
