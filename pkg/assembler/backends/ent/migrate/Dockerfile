FROM arigaio/atlas:latest-alpine@sha256:93915be7712b835d680a4d8239175f17fc577013ad62e345bb6936b38cff155c

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
