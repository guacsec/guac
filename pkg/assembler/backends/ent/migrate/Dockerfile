FROM arigaio/atlas:latest-alpine@sha256:b7a7ce394c3f78a6771b4047b1d622122b43636b2a382f37cec5f2b6a4153d7a

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
