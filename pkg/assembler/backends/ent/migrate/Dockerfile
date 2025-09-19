FROM arigaio/atlas:latest-alpine@sha256:a5d7c9b73b8559e745934c468e011ffeaa687f7fa7e5041ef71f14889559875a

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
