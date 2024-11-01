FROM arigaio/atlas:latest-alpine@sha256:5eac9e376bcd8d3605b62902f69ee989690d2694fd16d9ee1c2f79fba811f5e6

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
