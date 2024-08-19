# atlas migration

This dockerfile allows for running atlas migration for ENT.

1. docker build: `docker build . -t atlas-migration`
1. Run via:

To run it on a local server (for example: `postgres://guac:guac@0.0.0.0:5432/guac?search_path=public&sslmode=disable`):
```
docker run -e PGHOST=host.docker.internal \
           -e PGPORT=5432 \
           -e PGDATABASE=guac \
           -e PGUSER=guac \
           -e PGPASSWORD=guac \
           --network bridge \
           atlas-migration
````

For remote servers:

```
docker run -e PGHOST=your_host \
           -e PGPORT=your_port \
           -e PGDATABASE=your_database \
           -e PGUSER=your_user \
           -e PGPASSWORD=your_password \
           atlas-migration
```