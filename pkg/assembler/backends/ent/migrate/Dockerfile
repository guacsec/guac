FROM arigaio/atlas:latest-alpine@sha256:dcce9b6df2e98ddbd9ff987ec2072ed83f92c0c13965f166c0db7e5ce8f0792f

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
