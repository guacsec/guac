FROM arigaio/atlas:latest-alpine@sha256:6c4f0b31d10bd9797254f4acc535bca750b50168886240e62f232d3225163d18

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
