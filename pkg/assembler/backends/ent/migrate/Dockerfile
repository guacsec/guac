FROM arigaio/atlas:latest-alpine@sha256:dc476fac1f2f48fb5638bc3494fa81dba03ceada54af5c9f7078ec37d8c09083

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
