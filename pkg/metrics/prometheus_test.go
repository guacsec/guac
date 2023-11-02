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
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMetrics(t *testing.T) {
	ctx := WithMetrics(context.Background())
	collector := FromContext(ctx)

	_, err := collector.RegisterCounter(ctx, "test_counter", "label1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = collector.RegisterHistogram(ctx, "test_histogram", "label1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = collector.RegisterGauge(ctx, "test_gauge", "label1")
	if err != nil {
		t.Fatal(err)
	}

	_, err = collector.RegisterGauge(ctx, "test_gauge", "label1")
	if err == nil {
		t.Fatal("expected error")
	}

	time.Sleep(1 * time.Second)

	handler := collector.MetricsHandler()

	req, err := http.NewRequest("GET", "/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	err = collector.ObserveHistogram(ctx, "test_histogram", 2.5, "label1")
	if err != nil {
		t.Fatal(err)
	}

	err = collector.AddCounter(ctx, "test_counter", 1, "label1")
	if err != nil {
		t.Fatal(err)
	}

	err = collector.SetGauge(ctx, "test_gauge", 1.5, "label1")
	if err != nil {
		t.Fatal(err)
	}
	err = collector.AddCounter(ctx, "non_existing_counter", 1, "label1")
	if err == nil {
		t.Fatal("expected error for non-existing counter")
	}

	assertMetricRegistered(t, "guac_test_histogram")
	assertMetricRegistered(t, "guac_test_counter")
	assertMetricRegistered(t, "guac_test_gauge")

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	expected := `guac_test_counter{label1="label1"}`
	if !strings.Contains(rr.Body.String(), expected) {
		t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), expected)
	}
}

func assertMetricRegistered(t *testing.T, metricName string) {
	count, err := testutil.GatherAndCount(prometheus.DefaultGatherer, metricName)
	if err != nil {
		t.Errorf("Failed to gather and count: %v", err)
	}
	if count == 0 {
		t.Errorf("%s is not registered", metricName)
	}
}
