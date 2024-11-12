FROM arigaio/atlas:latest-alpine@sha256:abe7313979686c6ff0042368775e04a2a6ceb8ad3783b3969ffce597d38c7422

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
