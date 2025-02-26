FROM arigaio/atlas:latest-alpine@sha256:b5c91e15ecc1b0d764c52836877fc614b7bc1659abb8c55f0f019cbe44a0126c

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
