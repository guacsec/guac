FROM arigaio/atlas:latest-alpine@sha256:50ea945d781abc223673396da451d0b61a246a7c41f09f4e636cd5162b65d152

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
