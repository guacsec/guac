#!/bin/sh
atlas migrate apply --dir file:///app/migrations --url "postgres://$PGUSER:$PGPASSWORD@$PGHOST:$PGPORT/$PGDATABASE?sslmode=disable"
