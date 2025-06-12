FROM arigaio/atlas:latest-alpine@sha256:2f717980ae557b3b713f7f4ce9b11f0c060070beff869698c309e95a92b7752f

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
