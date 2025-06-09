FROM arigaio/atlas:latest-alpine@sha256:49c5c475d69defd954f1363162a272c6182ab45ad97f97d2482ad75a1eddb868

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
