FROM arigaio/atlas:latest-alpine@sha256:21ca10cf335e3e2ff9c2b564700c8d6ea0aafa90505e1441ec2cefd71da7adc5

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Create non-root user and switch to it
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

ENTRYPOINT ["/app/entrypoint.sh"]
