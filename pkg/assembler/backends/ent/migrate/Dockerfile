FROM arigaio/atlas:latest-alpine@sha256:46a9a0e7210e6f10298e335e663e05028d6904d49cec57486ae0dfa29b0eef81

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
