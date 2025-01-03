FROM arigaio/atlas:latest-alpine@sha256:9bb6dfcbc6dedd0393ce5f9fcb71662876cc6860ea896eb0b986da41202bd7a3

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
