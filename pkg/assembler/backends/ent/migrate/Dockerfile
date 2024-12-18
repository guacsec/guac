FROM arigaio/atlas:latest-alpine@sha256:d61e11c6f69383e0c01122993af3978395f3fbfe6cc1611986b7232dc485553b

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
