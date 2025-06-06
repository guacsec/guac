FROM arigaio/atlas:latest-alpine@sha256:8e6c294b25396a0990ad550c6e656c87294e0a226f51e60490c769902413bae2

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
