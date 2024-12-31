FROM arigaio/atlas:latest-alpine@sha256:f48103637c89cdd1494a1295ee9daf88a6c8514ae8abc1ae3397c6cac838ba4d

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
