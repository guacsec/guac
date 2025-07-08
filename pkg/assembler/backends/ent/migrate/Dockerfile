FROM arigaio/atlas:latest-alpine@sha256:bcc16858f0445d29f9896b789c3603272fcf794fd30c766d3833453548e66f3d

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
