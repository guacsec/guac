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
	"net/http"
)

// Observable is an interface that allows for observing a float64 value.
type Observable interface {
	Observe(float64)
}

// Counter is an interface that allows for incrementing and adding a float64 value.
type Counter interface {
	Inc()
	Add(float64)
}

// MetricCollector is an interface that provides methods for registering and manipulating metrics.
type MetricCollector interface {
	// RegisterHistogram registers a histogram metric with the given name and labels.
	RegisterHistogram(ctx context.Context, name string, labels ...string) (Observable, error)
	// RegisterGauge registers a gauge metric with the given name and labels.
	RegisterGauge(ctx context.Context, name string, labels ...string) (Counter, error)
	// RegisterCounter registers a counter metric with the given name and labels.
	RegisterCounter(ctx context.Context, name string, labels ...string) (Counter, error)
	// ObserveHistogram observes a value for the histogram metric with the given name and labels.
	ObserveHistogram(ctx context.Context, name string, value float64, labels ...string) error
	// SetGauge sets a value for the gauge metric with the given name and labels.
	SetGauge(ctx context.Context, name string, value float64, labels ...string) error
	// AddCounter adds a value to the counter metric with the given name and labels.
	AddCounter(ctx context.Context, name string, value float64, labels ...string) error
	// MetricsHandler returns an http.Handler for serving the metrics.
	MetricsHandler() http.Handler
	// MeasureFunctionExecutionTime measures the execution time of a function with the given name.
	MeasureFunctionExecutionTime(ctx context.Context, name string) (func(), error)
	// UnregisterCounter unregisters the counter metric with the given name and labels.
	UnregisterCounter(ctx context.Context, name string, labels ...string) error
	// UnregisterHistogram unregisters the histogram metric with the given name and labels.
	UnregisterHistogram(ctx context.Context, name string, labels ...string) error
	// UnregisterGauge unregisters the gauge metric with the given name and labels.
	UnregisterGauge(ctx context.Context, name string, labels ...string) error
}
