FROM arigaio/atlas:latest-alpine@sha256:ef040257e64d8fa461e778c4fb441064de01347ce712cf6eb11b4971193e58b1

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
