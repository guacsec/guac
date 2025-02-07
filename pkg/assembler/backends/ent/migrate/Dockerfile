FROM arigaio/atlas:latest-alpine@sha256:22e1860aef01a75e3661f281821dc113e40dda329ef0db2315faa703f522e6de

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
