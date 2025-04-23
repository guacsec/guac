FROM arigaio/atlas:latest-alpine@sha256:7990ed7b7118bd470e6fd51db65ff4edf77bc1cfe99147f5a4e8e7b2c33f1029

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
