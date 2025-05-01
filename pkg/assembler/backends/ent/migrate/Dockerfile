FROM arigaio/atlas:latest-alpine@sha256:52e193a49c8afabdc98ec8794b90949ba4f16a01cc61d6d97f849384fabcb08a

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
