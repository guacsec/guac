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

package mockclearlydefined

// this package is used to mock the clearlydefined api for testing purposes
// to use it you should create a new instance of MockClearlyDefined
// then you can query for the actual pURLs you wish to mock and add them
// to the testdata, then you can pass them in as a mapping from coordinates
// to the definition bytes. To convert pURLs to coordinates you can use 
// github.com/guacsec/guac/pkg/misc/coordinates::ConvertPurlToCoordinate

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
)

type MockClearlyDefined struct {
	server      *httptest.Server
	definitions map[string]interface{}
}

func NewMockClearlyDefined() *MockClearlyDefined {
	mock := &MockClearlyDefined{
		definitions: make(map[string]interface{}),
	}

	mock.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mock.defaultHandler(w, r)
	}))

	return mock
}

func (m *MockClearlyDefined) GetTransport() *MockTransport {
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
	if strings.Contains(req.URL.Host, "api.clearlydefined.io") {
		// modify the request to point to the test server
		req.URL.Scheme = "http"
		req.URL.Host = strings.TrimPrefix(t.TestServerURL, "http://")
	}
	return t.OriginalTransport.RoundTrip(req)
}

func (m *MockClearlyDefined) Close() {
	_ = m.server.Close()
}

func (m *MockClearlyDefined) SetDefinitions(definitions map[string][]byte) error {
	// we should parse each definition as json
	for coord, definition := range definitions {
		temp := make(map[string]interface{})
		err := json.Unmarshal(definition, &temp)
		if err != nil {
			return err
		}
		m.definitions[coord] = temp
	}
	return nil
}

// defaultHandler is the default response handler for the mock server
func (m *MockClearlyDefined) defaultHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" && strings.Contains(r.URL.Path, "/definitions") {
		// extract the body
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		// the body should be a json array of strings which are just coordinates
		// e.g. ["sourcearchive/mavencentral/org.apache.logging.log4j/log4j-core/2.8.1","sourcearchive/mavencentral/org.apache.commons/commons-text/1.9"]
		// so we can parse it as json
		coordinates := []string{}
		err := json.Unmarshal(body, &coordinates)
		if err != nil {
			http.Error(w, "Failed to parse request body", http.StatusInternalServerError)
			return
		}

		// for each coordinate we need to check if we have a definition for it
		// if we do we return it, if not we return a 404
		// we might also have multiple coordinates in the request
		// when there are multiple coordinates we can return them as a dictionary
		// with the key being the coordinate and the value being the definition
		var response map[string]interface{}
		for _, coord := range coordinates {
			if definition, ok := m.definitions[coord]; ok {
				if response == nil {
					response = make(map[string]interface{})
				}
				response[coord] = definition
			}
		}

		if response != nil {
			w.WriteHeader(http.StatusOK)
			err = json.NewEncoder(w).Encode(response)
			if err != nil {
				http.Error(w, "Failed to encode response", http.StatusInternalServerError)
				return
			}
			return
		}
	}

	// catch all
	http.Error(w, "Not found", http.StatusNotFound)
}
