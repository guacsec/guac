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

package mockosv

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"

	osv_scanner "github.com/google/osv-scanner/pkg/osv"
)

type MockOSV struct {
	server    *httptest.Server
	responses map[string][]string
}

func NewMockOSV() *MockOSV {
	mock := &MockOSV{
		responses: map[string][]string{
			"pkg:maven/org.apache.commons/commons-text@1.9": {
				"GHSA-599f-7c49-w659",
			},
			"pkg:maven/org.apache.logging.log4j/log4j-core@2.8.1": {
				"GHSA-3pxv-7cmr-fjr4",
				"GHSA-7rjr-3q55-vv33",
				"GHSA-8489-44mv-ggj8",
				"GHSA-fxph-q3j8-mv87",
				"GHSA-jfh8-c2jp-5v3q",
				"GHSA-p6xc-xr62-6r2g",
				"GHSA-vc5p-v9hr-52mj",
				"GHSA-vwqq-5vrc-xw9h",
			},
			"pkg:maven/io.vertx/vertx-core@4.3.7?type=jar": {
				"GHSA-3g76-f9xq-8vp6",
				"GHSA-9ph3-v2vh-3qx7",
				"GHSA-cphf-4846-3xx9",
			},
			"pkg:maven/io.vertx/vertx-web@4.3.7?type=jar": {
				"GHSA-45p5-v273-3qqr",
				"GHSA-53jx-vvf9-4x38",
				"GHSA-h5fg-jpgr-rv9c",
			},
		},
	}

	mock.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mock.defaultHandler(w, r)
	}))

	return mock
}

func (m *MockOSV) Close() {
	m.server.Close()
}

func (m *MockOSV) GetTransport() *MockTransport {
	return &MockTransport{
		OriginalTransport: http.DefaultTransport,
		TestServerURL:     m.server.URL,
	}
}

type MockTransport struct {
	OriginalTransport http.RoundTripper
	TestServerURL     string
}

func (t *MockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.Contains(req.URL.Host, "osv.dev") {
		req.URL.Scheme = "http"
		req.URL.Host = strings.TrimPrefix(t.TestServerURL, "http://")
	}
	return t.OriginalTransport.RoundTrip(req)
}

func (m *MockOSV) SetResponses(responses map[string][]string) {
	for k, v := range responses {
		m.responses[k] = v
	}
}

func (m *MockOSV) defaultHandler(w http.ResponseWriter, r *http.Request) {
	var query osv_scanner.BatchedQuery
	if err := json.NewDecoder(r.Body).Decode(&query); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var batchedResp osv_scanner.BatchedResponse
	for _, q := range query.Queries {
		purl := q.Package.PURL
		vulnIDs := m.responses[purl]

		var vulns []osv_scanner.MinimalVulnerability
		for _, id := range vulnIDs {
			vulns = append(vulns, osv_scanner.MinimalVulnerability{
				ID: id,
			})
		}
		batchedResp.Results = append(batchedResp.Results, osv_scanner.MinimalResponse{
			Vulns: vulns,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(batchedResp)
}