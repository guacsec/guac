FROM arigaio/atlas:latest-alpine@sha256:175e15da98f7f95e01f6a69fc54d0e3e25703f690a0dd275200283d8b5daa8c1

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
