FROM arigaio/atlas:latest-alpine@sha256:a33d6cb883517619c47e76ba46808ca3ed40ebc082179fa4255333d70dd546e0

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
