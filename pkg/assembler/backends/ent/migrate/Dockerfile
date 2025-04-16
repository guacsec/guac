FROM arigaio/atlas:latest-alpine@sha256:53e22909368fe7e8e218529b8a6367d585ee0e31f3fca6dbf4152d61e39709c6

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
