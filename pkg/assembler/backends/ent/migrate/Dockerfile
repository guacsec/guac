FROM arigaio/atlas:latest-alpine@sha256:3b0d8fb84be09b4f597f87bdc233c39f73d52082041e0d0432e40005cc6f25b2

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
