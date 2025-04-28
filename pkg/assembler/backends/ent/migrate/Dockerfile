FROM arigaio/atlas:latest-alpine@sha256:340f7aa8b002f342d57bc587bb1f67a20fea1e70122420032a4f4a74b7cb0092

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
