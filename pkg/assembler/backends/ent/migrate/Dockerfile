FROM arigaio/atlas:latest-alpine@sha256:6944a93abf86fc8579b26b651db60858a3cdfa8d2da9c4dcdc978b10baa917f3

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
