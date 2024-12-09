FROM arigaio/atlas:latest-alpine@sha256:0bb766dae3dc2cc175746e5d784e92f66ac5bb3c59ad9ff60ee773b373873174

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
