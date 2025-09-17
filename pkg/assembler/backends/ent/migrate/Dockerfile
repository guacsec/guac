FROM arigaio/atlas:latest-alpine@sha256:483595ca5ac58b05184485bef9da2378a66f20412d6d95504a2559939daf9263

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
