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
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
)

type prom struct {
	counters map[string]prometheus.Counter
	summary  map[string]prometheus.Summary
}

// NewPrometheus returns a new prometheus metrics implementation
func NewPrometheus() Metrics {
	return &prom{
		counters: make(map[string]prometheus.Counter),
		summary:  make(map[string]prometheus.Summary),
	}
}

// NewCounter creates a new counter metric
func (p *prom) NewCounter(name string) error {
	if _, ok := p.counters[name]; ok {
		return fmt.Errorf("counter %s already exists", name)
	}
	counter := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_total", name),
			Help: fmt.Sprintf("The total number of %s function calls", name),
		})
	prometheus.MustRegister(counter)
	p.counters[name] = counter
	return nil
}

// IncrementCounter increments a counter metric
func (p *prom) IncrementCounter(funcName string) {
	p.counters[funcName].Inc()
}

// NewSummary creates a new summary metric
func (p *prom) NewSummary(name string) error {
	if _, ok := p.summary[name]; ok {
		return fmt.Errorf("summary %s already exists", name)
	}
	summary := prometheus.NewSummary(
		prometheus.SummaryOpts{
			Name: fmt.Sprintf("%s_summary", name),
			Help: fmt.Sprintf("The summary of %s function calls", name),
		})
	prometheus.MustRegister(summary)
	p.summary[name] = summary
	return nil
}

// ObserveSummary records a value for a summary metric
func (p *prom) ObserveSummary(funcName string, duration float64) {
	p.summary[funcName].Observe(duration)
}
