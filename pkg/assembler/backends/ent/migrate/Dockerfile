FROM arigaio/atlas:latest-alpine@sha256:bf1fe9e6db8c7d460afa00c721f19fefb9ad1b607b6613fd10647c0a615997f9

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
