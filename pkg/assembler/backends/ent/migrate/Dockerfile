FROM arigaio/atlas:latest-alpine@sha256:1f2ef659e17b8fb9574a2911b1616067da439000eb8692df1e8e26fa77393017

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
