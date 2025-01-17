FROM arigaio/atlas:latest-alpine@sha256:f8c6b695bbbac7faa58124e49f7f9eaf80ae950e73071a7d4adb302060c7d4c2

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
