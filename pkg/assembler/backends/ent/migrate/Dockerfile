FROM arigaio/atlas:latest-alpine@sha256:dc46240d3bf91e4577f26f4e59065f7deddfa88e895e1fbffa670afe4a7acce8

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
