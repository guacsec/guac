FROM arigaio/atlas:latest-alpine@sha256:b56c29fea099909a3642f4c22032837c2ccc4b9c454602573396bb5223993e8d

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
