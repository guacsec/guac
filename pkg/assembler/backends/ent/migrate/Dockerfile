FROM arigaio/atlas:latest-alpine@sha256:df1f87477ae19ab321e117290f1722f1d60e2a9754a94ed15426ea0f0972406b

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
