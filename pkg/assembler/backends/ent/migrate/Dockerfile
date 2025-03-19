FROM arigaio/atlas:latest-alpine@sha256:91d3de37c2baf941d5570ecd20edaecd197b5c122111257cd248a32febbb81e7

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
