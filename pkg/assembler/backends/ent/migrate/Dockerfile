FROM arigaio/atlas:latest-alpine@sha256:cb9802bd1350aaf346bf3684a7b0152cc24d291bd87184e022f480fa42de4d76

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
