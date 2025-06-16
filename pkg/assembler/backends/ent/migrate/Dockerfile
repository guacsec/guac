FROM arigaio/atlas:latest-alpine@sha256:02ea84b091d7d00c57a87c0e1fb7a6a0e7766793d1459f64aed5cc870f3223a8

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
