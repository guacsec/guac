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
//

// Package metrics provides a set of interfaces and methods for collecting
// and registering metrics in the application. It includes support for
// counters, histograms, gauges, and other statistical measures.
//
// The package is designed around interfaces, allowing for easy swapping
// of different metrics systems and facilitating testing. Currently, it is
// based on the Prometheus implementation.
//
// Example usage:
//
//     // Register a new counter
//     if _, err := metrics.RegisterCounter(ctx, GetVersionErrorsCounter, "Count of get version errors"); err != nil {
//         return fmt.Errorf("failed to register counter for get version errors: %w", err)
//     }
//
//     // Register a new gauge
//     if _, err := metrics.RegisterGauge(ctx, "active_requests", "Number of active requests"); err != nil {
//         return fmt.Errorf("failed to register gauge for active requests: %w", err)
//     }
//
//     // Register a new histogram
//     if _, err := metrics.RegisterHistogram(ctx, GetVersionDurationHistogram, "Duration of get version", "duration"); err != nil {
//         return fmt.Errorf("failed to register histogram for get version duration: %w", err)
//     }
//
//     // Register the HTTP handler
//     http.Handle("/metrics", promhttp.Handler())
//
//     // Get the metrics collector from the context
//     metrics := metrics.FromContext(ctx)
//
//     // Measure function execution time
//     defer metrics.MeasureFunctionExecutionTime(ctx, GetVersionDurationHistogram)
//
//     // Add to a counter
//     metrics.AddCounter(ctx, GetVersionErrorsCounter, 1, pkgType)
//
//     // Set a gauge
//     metrics.SetGauge(ctx, "active_requests", 5)
//

package metrics
