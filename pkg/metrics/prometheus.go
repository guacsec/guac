//
// Copyright 2023 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package metrics

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	functionDuration = "function_duration_seconds"
	collectorKey     = "metrics"
)

var registerOnce sync.Once

type metrics string

// prometheusCollector is a struct that holds the maps for histograms, gauges, and counters.
type prometheusCollector struct {
	// histograms is a map that holds the HistogramVec objects.
	histograms map[string]*prometheus.HistogramVec
	// gauges is a map that holds the GaugeVec objects.
	gauges map[string]*prometheus.GaugeVec
	// counters is a map that holds the CounterVec objects.
	counters map[string]*prometheus.CounterVec
	// prefix is a string that holds the prefix for the metrics.
	name     string
	registry *prometheus.Registerer
}

// SetGauge sets a gauge metric with a given name, value, and labels.
func (p *prometheusCollector) SetGauge(_ context.Context, name string, value float64, labels ...string) error {
	name = fmt.Sprintf("%s_%s", p.name, name)
	if _, ok := p.gauges[name]; !ok {
		return fmt.Errorf("gauge '%s' not found", name)
	}
	p.gauges[name].WithLabelValues(labels...).Set(value)
	return nil
}

// AddHistogram increments a histogram metric with a given name, value, and labels.
func (p *prometheusCollector) AddHistogram(_ context.Context, name string, value float64, labels ...string) error {
	name = fmt.Sprintf("%s_%s", p.name, name)
	if _, ok := p.histograms[name]; !ok {
		return fmt.Errorf("histogram '%s' not found", name)
	}
	p.histograms[name].WithLabelValues(labels...).Observe(value)
	return nil
}

// AddCounter increments a counter metric with a given name, value, and labels.
// It returns an error if the counter is not found.
func (p *prometheusCollector) AddCounter(_ context.Context, name string, value float64, labels ...string) error {
	name = fmt.Sprintf("%s_%s", p.name, name)
	if _, ok := p.counters[name]; !ok {
		return fmt.Errorf("counter '%s' not found", name)
	}
	p.counters[name].WithLabelValues(labels...).Add(value)
	return nil
}

// MetricsHandler returns a http.Handler for the prometheus metrics.
func (p *prometheusCollector) MetricsHandler() http.Handler {
	return promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})
}

// NewPrometheus creates a new prometheusCollector with empty sync.Maps for histograms, gauges, and counters.

// NewPrometheus creates a new prometheusCollector with empty sync.Maps for histograms, gauges, and counters.
func NewPrometheus(name string) MetricCollector {
	prefix := fmt.Sprintf("%s_%s_function_duration_seconds", "guac", name)
	functionDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    prefix,
			Help:    "Time spent executing functions.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"function"},
	)
	p := &prometheusCollector{
		histograms: make(map[string]*prometheus.HistogramVec),
		gauges:     make(map[string]*prometheus.GaugeVec),
		counters:   make(map[string]*prometheus.CounterVec),
		name:       name,
		registry:   &prometheus.DefaultRegisterer,
	}
	p.histograms[prefix] = functionDuration
	// Register the http_server_request_duration_seconds histogram
	responseTimeHistogram := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: p.name,
		Name:      "http_server_request_duration_seconds",
		Help:      "Histogram of response time for handler in seconds",
		Buckets:   []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
	}, []string{"route", "method", "status_code"})
	p.histograms["http_server_request_duration_seconds"] = responseTimeHistogram

	p.histograms["http_server_request_duration_seconds"] = responseTimeHistogram
	registerOnce.Do(func() {
		(*p.registry).MustRegister(responseTimeHistogram)
	})

	return p
}

// RegisterGauge registers a gauge metric with the given name and labels.
func (p *prometheusCollector) RegisterGauge(_ context.Context, name string, labels ...string) (Counter, error) {
	name = fmt.Sprintf("%s_%s", p.name, name)
	if _, ok := p.gauges[name]; ok {
		return nil, fmt.Errorf("gauge '%s' already registered", name)
	}
	gaugeVec := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name:      name,
		Help:      "Gauge for " + name,
		Namespace: "guac",
	}, labels)
	p.gauges[name] = gaugeVec
	if err := prometheus.Register(gaugeVec); err != nil {
		return nil, fmt.Errorf("failed to register gauge '%s': %v", name, err)
	}
	return gaugeVec.WithLabelValues(labels...), nil
}

// RegisterCounter registers a counter metric with the given name and labels.
func (p *prometheusCollector) RegisterCounter(_ context.Context, name string, labels ...string) (Counter, error) {
	name = fmt.Sprintf("%s_%s", p.name, name)
	if _, ok := p.counters[name]; ok {
		return nil, fmt.Errorf("counter '%s' already registered", name)
	}
	counterVec := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      name,
		Help:      "Counter for " + name,
		Namespace: "guac",
	}, labels)
	p.counters[name] = counterVec
	if err := prometheus.Register(counterVec); err != nil {
		return nil, fmt.Errorf("failed to register counter '%s': %v", name, err)
	}
	return counterVec.WithLabelValues(labels...), nil
}

// RegisterHistogram registers a histogram metric with the given name and labels.
func (p *prometheusCollector) RegisterHistogram(_ context.Context, name string, labels ...string) (Observable, error) {
	name = fmt.Sprintf("%s_%s", p.name, name)
	if _, ok := p.histograms[name]; ok {
		return nil, fmt.Errorf("histogram '%s' already registered", name)
	}
	histogramVec := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:      name,
		Help:      "Histogram for " + name,
		Namespace: "guac",
	}, labels)
	p.histograms[name] = histogramVec

	if err := prometheus.Register(histogramVec); err != nil {
		return nil, fmt.Errorf("failed to register histogram '%s': %v", name, err)
	}
	return histogramVec.WithLabelValues(labels...), nil
}

// WithMetrics returns a new context with a prometheusCollector.
func WithMetrics(ctx context.Context, name string) context.Context {
	metricsCollector := NewPrometheus(name)
	return context.WithValue(ctx, metrics(collectorKey), metricsCollector)
}

// MeasureFunctionExecutionTime measures the time duration of a function execution.
// It can be used with defer to measure the duration of a function.
// Example usage:
//
//	defer p.MeasureFunctionExecutionTime(ctx, "myFunction", "label1", "label2")()
func (p *prometheusCollector) MeasureFunctionExecutionTime(_ context.Context, name string) (func(), error) {
	name = fmt.Sprintf("%s_%s", p.name, name)
	if _, ok := p.histograms[functionDuration]; !ok {
		return nil, fmt.Errorf("histogram '%s' not found", name)
	}
	start := time.Now()
	return func() {
		duration := time.Since(start)
		p.histograms[functionDuration].WithLabelValues([]string{name}...).Observe(duration.Seconds())
	}, nil
}

// ObserveHistogram observes a histogram metric with a given name, value, and labels.
func (p *prometheusCollector) ObserveHistogram(_ context.Context, name string, value float64, labels ...string) error {
	name = fmt.Sprintf("%s_%s", p.name, name)
	if _, ok := p.histograms[name]; !ok {
		return fmt.Errorf("histogram '%s' not found", name)
	}
	p.histograms[name].WithLabelValues(labels...).Observe(value)
	return nil
}

// UnregisterCounter unregisters the counter metric with the given name and labels.
func (p *prometheusCollector) UnregisterCounter(_ context.Context, name string, labels ...string) error {
	name = fmt.Sprintf("%s_%s", p.name, name)
	if _, ok := p.counters[name]; !ok {
		// If the counter is not found, return nil. Probably the counter was already unregistered.
		return nil
	}
	prometheus.Unregister(p.counters[name])
	delete(p.counters, name)
	return nil
}

// UnregisterHistogram unregisters the histogram metric with the given name and labels.
func (p *prometheusCollector) UnregisterHistogram(_ context.Context, name string, labels ...string) error {
	name = fmt.Sprintf("%s_%s", p.name, name)
	if _, ok := p.histograms[name]; !ok {
		// If the histogram is not found, return nil. Probably the histogram was already unregistered.
		return nil
	}
	prometheus.Unregister(p.histograms[name])
	delete(p.histograms, name)
	return nil
}

// UnregisterGauge unregisters the gauge metric with the given name and labels.
func (p *prometheusCollector) UnregisterGauge(_ context.Context, name string, labels ...string) error {
	name = fmt.Sprintf("%s_%s", p.name, name)
	if _, ok := p.gauges[name]; !ok {
		// If the gauge is not found, return nil. Probably the gauge was already unregistered.
		return nil
	}
	prometheus.Unregister(p.gauges[name])
	delete(p.gauges, name)
	return nil
}

// FromContext returns the MetricCollector from the context.
func FromContext(ctx context.Context, name string) MetricCollector {
	c := metrics(collectorKey)
	if met, ok := ctx.Value(c).(MetricCollector); ok {
		return met
	}
	return NewPrometheus(name)
}

// statusRecorder to record the status code from the ResponseWriter
type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (rec *statusRecorder) WriteHeader(statusCode int) {
	rec.statusCode = statusCode
	rec.ResponseWriter.WriteHeader(statusCode)
}

// MeasureGraphQLResponseDuration creates a middleware that records the response time and status code
func (pc *prometheusCollector) MeasureGraphQLResponseDuration(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create a copy of the request body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		r.Body = io.NopCloser(bytes.NewBuffer(body)) // Replace the request body with a copy

		// Create another copy for JSON unmarshalling
		bodyCopy := make([]byte, len(body))
		copy(bodyCopy, body)

		// Parse the operation name from the request body copy
		var graphqlRequest struct {
			OperationName string `json:"operationName"`
		}
		err = json.Unmarshal(bodyCopy, &graphqlRequest)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		rec := statusRecorder{w, http.StatusOK}

		next.ServeHTTP(&rec, r)

		duration := time.Since(start)
		statusCode := strconv.Itoa(rec.statusCode)

		// Use the pre-registered histogram
		if histogram, ok := pc.histograms["http_server_request_duration_seconds"]; ok {
			histogram.WithLabelValues(graphqlRequest.OperationName, r.Method, statusCode).Observe(duration.Seconds())
		}
	})
}
