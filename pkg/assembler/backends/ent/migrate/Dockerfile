FROM arigaio/atlas:latest-alpine@sha256:b4b4ba671ceb327ab7e9b3d0dbf4546b82217cd90be7f9e9ac9bc5767a31ad27

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
