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
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestRegisterCounter(t *testing.T) {
	ctx := WithMetrics(context.Background(), "guac_test")
	collector := FromContext(ctx, "guac_test")

	counter, err := collector.RegisterCounter(ctx, "test_counter", "label1")
	if err != nil {
		t.Fatal(err)
	}

	err = collector.AddCounter(ctx, "test_counter", 1, "label1")
	if err != nil {
		t.Fatal(err)
	}

	// Validate the counter
	counterVec, ok := counter.(prometheus.Collector)
	if !ok {
		t.Fatal("counter is not a Collector")
	}
	err = testutil.CollectAndCompare(counterVec, strings.NewReader(`
	    # HELP guac_guac_test_test_counter Counter for guac_test_test_counter
		# TYPE guac_guac_test_test_counter counter
		guac_guac_test_test_counter{label1="label1"} 1
	`))
	if err != nil {
		t.Fatal(err)
	}
}

func TestRegisterHistogram(t *testing.T) {
	ctx := WithMetrics(context.Background(), "guac_test")
	collector := FromContext(ctx, "guac_test")

	_, err := collector.RegisterHistogram(ctx, "test_histogram", "label1")
	if err != nil {
		t.Fatal(err)
	}

	err = collector.ObserveHistogram(ctx, "test_histogram", 2.5, "label1")
	if err != nil {
		t.Fatal(err)
	}
}

func TestRegisterGauge(t *testing.T) {
	ctx := WithMetrics(context.Background(), "guac_test")
	collector := FromContext(ctx, "guac_test")

	gaugeVec, err := collector.RegisterGauge(ctx, "test_gauge", "label1")
	if err != nil {
		t.Fatal(err)
	}

	a, ok := gaugeVec.(prometheus.Collector)
	if !ok {
		t.Fatal("gaugeVec is not a Collector")
	}
	gaugeVec.Add(1)
	err = testutil.CollectAndCompare(a, strings.NewReader(`
	    # HELP guac_guac_test_test_gauge Gauge for guac_test_test_gauge
		# TYPE guac_guac_test_test_gauge gauge
		guac_guac_test_test_gauge{label1="label1"} 1
	`))
	if err != nil {
		t.Fatal(err)
	}
}

func TestMetricsHandler(t *testing.T) {
	ctx := WithMetrics(context.Background(), "guac_test")
	collector := FromContext(ctx, "guac_test")

	handler := collector.MetricsHandler()

	req, err := http.NewRequest("GET", "/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
}

func TestNonExistingCounter(t *testing.T) {
	ctx := WithMetrics(context.Background(), "guac_test")
	collector := FromContext(ctx, "guac_test")

	err := collector.AddCounter(ctx, "non_existing_counter", 1, "label1")
	if err == nil {
		t.Fatal("expected error for non-existing counter")
	}
}
