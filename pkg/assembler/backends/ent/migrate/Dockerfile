FROM arigaio/atlas:latest-alpine@sha256:25fc9c9d10a542e6868d98d0dba265e478cdf3f9e947b91df7c5c06a083c826d

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
