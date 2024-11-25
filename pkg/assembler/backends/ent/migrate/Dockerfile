FROM arigaio/atlas:latest-alpine@sha256:1a13b85574cfe18b11d2c5269aefd83d886168a243f3ac52698350722689b6ed

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
