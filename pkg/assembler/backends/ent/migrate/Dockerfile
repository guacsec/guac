FROM arigaio/atlas:latest-alpine@sha256:cc6aec93cd02d25708e0b774b60c67ce1927bf15204b6e5836344afd178da521

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
