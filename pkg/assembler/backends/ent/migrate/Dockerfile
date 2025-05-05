FROM arigaio/atlas:latest-alpine@sha256:a919377a34a579bdcc5f33c1f376446204b5b915c5291e699d9de1f97812097a

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
