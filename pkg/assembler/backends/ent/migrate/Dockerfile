FROM arigaio/atlas:latest-alpine@sha256:404e6b4d180a1cbcadd9b42eacc72b1838bb7ad96284f7384f4fdf259c35e13f

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
