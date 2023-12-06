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
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	functionDuration = "function_duration_seconds"
	collectorKey     = "metrics"
)

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
	name string
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
func NewPrometheus(name string) MetricCollector {
	name = fmt.Sprintf("%s_%s_function_duration_seconds", "guac", name)
	functionDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    name,
			Help:    "Time spent executing functions.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"function"},
	)
	p := &prometheusCollector{
		histograms: make(map[string]*prometheus.HistogramVec),
		gauges:     make(map[string]*prometheus.GaugeVec),
		counters:   make(map[string]*prometheus.CounterVec),
	}
	p.histograms[name] = functionDuration
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

// FromContext returns the MetricCollector from the context.
func FromContext(ctx context.Context, name string) MetricCollector {
	c := metrics(collectorKey)
	if met, ok := ctx.Value(c).(MetricCollector); ok {
		return met
	}
	return NewPrometheus(name)
}
