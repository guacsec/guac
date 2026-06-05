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

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "github.com/guacsec/guac/pkg/assembler/backends/keyvalue"

	"github.com/guacsec/guac/internal/testing/stablememmap"
	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/metrics"
)

// TestQueryEndpointBadRequest covers issue #2195: posting an empty or malformed
// JSON body to the /query endpoint must return 400 Bad Request, not 500
// Internal Server Error. The handler is exercised together with the Prometheus
// metrics middleware because that middleware (not the GraphQL server) was the
// source of the original 500 response.
func TestQueryEndpointBadRequest(t *testing.T) {
	ctx := metrics.WithMetrics(context.Background(), "guac_query_test")

	store := stablememmap.GetStore()
	backend, err := backends.Get("keyvalue", ctx, store)
	if err != nil {
		t.Fatalf("Error getting backend: %v", err)
	}

	srv := GetGraphqlServer(ctx, backend)
	collector := metrics.FromContext(ctx, "guac_query_test")
	handler := collector.MeasureGraphQLResponseDuration(srv)

	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{
			name:       "empty body",
			body:       "",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "malformed json",
			body:       "{not json",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "valid query",
			body:       `{"query":"{ __typename }"}`,
			wantStatus: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/query", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != tc.wantStatus {
				t.Fatalf("POST /query with %s body: got status %d, want %d (body: %q)", tc.name, rr.Code, tc.wantStatus, rr.Body.String())
			}
		})
	}
}
