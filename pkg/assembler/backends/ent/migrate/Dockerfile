FROM arigaio/atlas:latest-alpine@sha256:86a55fee730dcd83a8e209602d42054bf0c9d856607e44013105fe864fc15846

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
