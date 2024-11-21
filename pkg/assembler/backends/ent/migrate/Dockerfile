FROM arigaio/atlas:latest-alpine@sha256:da62231ef4bebf6e6d6c4a1107dabc187cc639ee8df2d18ed83f624b6112543e

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
