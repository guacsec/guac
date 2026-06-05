//
// Copyright 2024 The GUAC Authors.
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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestMeasureGraphQLResponseDurationDoesNotShortCircuit guards against a
// regression of issue #2195: an empty or malformed request body used to make
// this metrics middleware return 500 before the request ever reached the
// GraphQL handler. The middleware must not decide request validity; it should
// pass the request through to the downstream handler (which answers with the
// correct status code for the payload) regardless of whether the body is valid
// JSON.
func TestMeasureGraphQLResponseDurationDoesNotShortCircuit(t *testing.T) {
	ctx := WithMetrics(context.Background(), "guac_graphql_test")
	collector := FromContext(ctx, "guac_graphql_test")

	// A downstream handler that echoes the body it received so we can assert
	// the middleware forwarded it unchanged.
	var sawBody string
	downstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		sawBody = string(b)
		w.WriteHeader(http.StatusOK)
	})

	handler := collector.MeasureGraphQLResponseDuration(downstream)

	tests := []struct {
		name string
		body string
	}{
		{name: "empty body", body: ""},
		{name: "malformed json", body: "{not json"},
		{name: "valid json with operation name", body: `{"operationName":"Q","query":"{ __typename }"}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sawBody = ""
			req := httptest.NewRequest(http.MethodPost, "/query", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			// The middleware must reach the downstream handler instead of
			// short-circuiting with a 500.
			if rr.Code != http.StatusOK {
				t.Fatalf("middleware short-circuited bad body: got status %d, want %d (request should reach downstream handler)", rr.Code, http.StatusOK)
			}
			if sawBody != tc.body {
				t.Fatalf("downstream received body %q, want %q (body must be forwarded unchanged)", sawBody, tc.body)
			}
		})
	}
}
