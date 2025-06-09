FROM arigaio/atlas:latest-alpine@sha256:7df1d33085c3afb07105f28520567e71dd339d47638729f6b120e6cbc14ecfbc

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
