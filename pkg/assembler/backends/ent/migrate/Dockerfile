FROM arigaio/atlas:latest-alpine@sha256:0c1473d495adeabf69bf82d9f12b4b2d864eced1fc561c253b7ca2521e811564

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
