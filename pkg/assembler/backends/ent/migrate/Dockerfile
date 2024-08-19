FROM alpine:3.18 AS migrations

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Install Atlas CLI
RUN apk add --no-cache curl && \
    curl -sSf https://atlasgo.sh | sh

FROM alpine:3.18

WORKDIR /app

COPY --from=migrations /app/migrations /app/migrations

COPY --from=migrations /usr/local/bin/atlas /usr/local/bin/atlas

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
