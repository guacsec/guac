FROM arigaio/atlas:latest-alpine@sha256:a491fa7377b987c3e9675763af52c541abf8cb81dc95a78676d69db83ac47a54

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
