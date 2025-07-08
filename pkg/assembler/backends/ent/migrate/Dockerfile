FROM arigaio/atlas:latest-alpine@sha256:5f0cca91d93df2d4194d2697116191e4f50dd76b697d0f6a4606acc4dcfacde0

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
