FROM arigaio/atlas:latest-alpine@sha256:397ab8151f3bc80ee95edb34ab869e0688e8f39fd0347de6154af8727a195a65

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
