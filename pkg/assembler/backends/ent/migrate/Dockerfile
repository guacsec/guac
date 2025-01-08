FROM arigaio/atlas:latest-alpine@sha256:777a287f22845b264e13dad0b3cea8a085a40b413d9060eafbb93dd5f19bd815

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
