FROM arigaio/atlas:latest-alpine@sha256:cb88e419697a029a92b59eab3ffefb111141fcea5075b3434a293bae27d39b8d

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
