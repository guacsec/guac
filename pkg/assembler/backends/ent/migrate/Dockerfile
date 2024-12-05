FROM arigaio/atlas:latest-alpine@sha256:2ac9ef14c687bb8c804fdee6e727c3137056c0b39879cbf93c96f4483637c445

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
