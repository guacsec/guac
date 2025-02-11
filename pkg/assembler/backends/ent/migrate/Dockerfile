FROM arigaio/atlas:latest-alpine@sha256:831c3992a1a0bf248d18413bdcc5eabe66707aec7ea79564f3731267aba2a6b6

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
