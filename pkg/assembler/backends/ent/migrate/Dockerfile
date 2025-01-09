FROM arigaio/atlas:latest-alpine@sha256:043d6d3a401280707d69d2866b26760bc8924bd163c6817413e2057ce85d9384

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
