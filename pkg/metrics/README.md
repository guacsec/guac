# Metrics

## Usage

This package provides a set of interfaces and implementations for collecting and exposing metrics in your application. The main interfaces are `MetricCollector`, `Observable`, and `Counter` which are defined in `metrics.go`. The `prometheus.go` file provides an implementation of these interfaces using the Prometheus monitoring system.

This package is easy to test as it is based on interfaces. You can create mock implementations of the `MetricCollector`, `Observable`, and `Counter` interfaces for testing purposes.

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
curl http://localhost:9091/metrics
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
