FROM arigaio/atlas:latest-alpine@sha256:d01cd1e3d941a4433e294955c6f357a6eae735eef90a721e94743a0419c802ad

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
