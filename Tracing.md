
ArangoDB, Jaeger, Prometheus, and Grafana are set up with arango.docker-compose.yaml

### Run the monitoring and tracing stack
`docker compose -f arango.docker-compose.yaml up`

The Jaeger UI is then available at http://localhost:16686/

The guacgql code is hardcoded to point to Jaeger at http://localhost:14268/api/traces at the moment.