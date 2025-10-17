FROM arigaio/atlas:latest-alpine@sha256:b2e145cb497ccbe8cd3319c080613af3edcd166d3a873b213b9d19e04f8d4724

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
