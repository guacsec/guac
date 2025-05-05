FROM arigaio/atlas:latest-alpine@sha256:c19a111b8ae380627ef1bec67e22cba4ed7a0a0f3277bdea14df7818f28cd6cb

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
