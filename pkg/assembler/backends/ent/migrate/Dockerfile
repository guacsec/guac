FROM arigaio/atlas:latest-alpine@sha256:d69b0574920ff6217470957cd3922f889160f8657590a36715fff40983deecdc

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
