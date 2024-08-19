#!/bin/sh

# Ensure all required environment variables are provided
if [ -z "$PGUSER" ] || [ -z "$PGPASSWORD" ] || [ -z "$PGHOST" ] || [ -z "$PGPORT" ] || [ -z "$PGDATABASE" ]; then
  echo "One or more required environment variables (PGUSER, PGPASSWORD, PGHOST, PGPORT, PGDATABASE) are missing."
  exit 1
fi

atlas migrate apply --dir file:///app/migrations --url "postgres://$PGUSER:$PGPASSWORD@$PGHOST:$PGPORT/$PGDATABASE?sslmode=disable"
