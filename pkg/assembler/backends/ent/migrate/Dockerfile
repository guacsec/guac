FROM arigaio/atlas:latest-alpine@sha256:0d94892c3a603b00cd8f9df70dee4b46fad4adf77b416b4dcf8927371f5a88f6

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
