FROM arigaio/atlas:latest-alpine@sha256:6bf345e5c8d9de5e399b55d05ea2728b6d19f1ee608c0dff31bafe676e15584d

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
