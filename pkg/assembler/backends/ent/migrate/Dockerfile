FROM arigaio/atlas:latest-alpine@sha256:b0fd3a2bb4f6d71416aad759f04ac16908ae131286a1a277880c9655154a7940

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
