FROM arigaio/atlas:latest-alpine@sha256:05f7b7d1ccdcee1c564df489edaaa636afdad1c914083bd920687a16161f3bc8

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
