FROM arigaio/atlas:latest-alpine@sha256:7b4ce29bf324f01cf20fb0d25544a15916b1f30350003dcb336ba8cfeca3cb31

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
