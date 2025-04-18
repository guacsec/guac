FROM arigaio/atlas:latest-alpine@sha256:17736533f3e4b087610824e933b1148af4d8d8a13601549d1ed40743ff055419

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
