FROM arigaio/atlas:latest-alpine@sha256:66caa34cca74c2b4175b53494467dba78794ef088e3d366b8d6910bf87cd90f4

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
