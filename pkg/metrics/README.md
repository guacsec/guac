# Metrics

## Otel metrics

GUAC is using Otel instrumented libraries for the following parts:

- HTTP GQL server in `guacgql`
- SQL library underneath the Ent/Postgres backend
- HTTP client for: OSV, ClearlyDefined, GitHub, EoL
- GRPC client for Deps.dev.

Any cli that runs one of the above will have the `enable-otel` cli option
available to setup the defult metric and trace providers. These are configured
to connect to an Otel collector over GRPC. Config uses the below defualt env
vars:

- `OTEL_EXPORTER_OTLP_ENDPOINT`: Address of Otel collector to connect to
- `OTEL_EXPORTER_OTLP_INSECURE`: If true, don't use TLS (local collector).
- `OTEL_SERVICE_NAME`: Service name attached to metrics

More details are available here:

- https://pkg.go.dev/go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc
- https://opentelemetry.io/docs/languages/sdk-configuration/general/#otel_traces_sampler

> Note: GUAC is not set up to define and publish custom metrics to
> Otel. I.e. the `MetricCollector` interface defined in this package does not
> (yet) support Otel metrics.

## Prometheus metrics

Prometheus metrics are available on many cli tools using the
`enable-prometheus` option. This starts an http server (if not already started)
and serves metrics on the `/metrics` endpoint. Custom metrics are available for
those GUAC packages that are manaully instrumented. The instructions for adding
manual instrumentation to other GUAC packages is described below:

### Usage

This package provides a set of interfaces and implementations for collecting
and exposing metrics in your application. The main interfaces are
`MetricCollector`, `Observable`, and `Counter` which are defined in
`metrics.go`. The `prometheus.go` file provides an implementation of these
interfaces using the Prometheus monitoring system.

This package is easy to test as it is based on interfaces. You can create mock
implementations of the `MetricCollector`, `Observable`, and `Counter`
interfaces for testing purposes.

### For New Packages

To use this metrics package in your application, you need to do the following:

1. Import the metrics package in your code.
2. Create a new instance of the `MetricCollector` using the `NewPrometheus()` function.
3. Use the `Register*` methods to register new metrics. You can register gauges, counters, and histograms.
4. Use the `SetGauge`, `AddCounter`, and `ObserveHistogram` methods to update the metrics.
5. Use the `MetricsHandler` method to get an `http.Handler` for serving the metrics.
6. Expose the `http.Handler` along with your HTTP server. Note that Prometheus does not start a server by itself, so you need to integrate it with your existing server or start a new one.

### To Scrape the Metrics
To scrape the metrics from Prometheus, you can use the following example:

```bash
curl http://localhost:8080/metrics
```

This will return a plain text page with a series of lines like this:

```bash
# TYPE go_memstats_stack_sys_bytes gauge
go_memstats_stack_sys_bytes 884736
# HELP go_memstats_sys_bytes Number of bytes obtained from system.
# TYPE go_memstats_sys_bytes gauge
go_memstats_sys_bytes 2.25188e+07
# HELP go_threads Number of OS threads created.
# TYPE go_threads gauge
go_threads 10
# HELP guac_http_deps_dev_version_errors Counter for http_deps_dev_version_errors
# TYPE guac_http_deps_dev_version_errors counter
guac_http_deps_dev_version_errors{name="antlr",namespace="github.com/antlr/antlr4/runtime/go",pkgtype="golang"} 2
guac_http_deps_dev_version_errors{name="api",namespace="github.com/hashicorp/vault",pkgtype="golang"} 1
guac_http_deps_dev_version_errors{name="consul",namespace="github.com/hashicorp",pkgtype="golang"} 1
guac_http_deps_dev_version_errors{name="name",namespace="namespace",pkgtype="pkgtype"} 0
guac_http_deps_dev_version_errors{name="readline",namespace="github.com/chzyer",pkgtype="golang"} 1
guac_http_deps_dev_version_errors{name="sdk",namespace="github.com/hashicorp/vault",pkgtype="golang"} 1
```
