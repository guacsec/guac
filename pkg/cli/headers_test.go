// Copyright 2024 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cli

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewHTTPHeaderTransport(t *testing.T) {
	type test struct {
		name        string
		headerFile  string
		wantErr     string
		wantHeaders map[string][]string
	}

	tests := []test{
		{
			name:       "creating a header transport with a non-existent file results in an error",
			headerFile: "does-not-exist.txt",
			wantErr:    "open does-not-exist.txt: no such file or directory",
		},
		{
			name:       "creating a header transport with a valid RFC 822 header file works",
			headerFile: "testdata/headers.txt",
			wantHeaders: map[string][]string{
				// values found in the header file
				"Hello":   {"World", "Goodbye"},
				"Goodbye": {"Galaxy"},
				"Header":  {"Value"},

				// other default headers set by the client
				"Accept-Encoding": {"gzip"},
				"User-Agent":      {"Go-http-client/1.1"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transport, err := NewHTTPHeaderTransport(test.headerFile, http.DefaultTransport)
			if err != nil {
				if err.Error() == test.wantErr {
					return
				} else if test.wantErr == "" {
					t.Fatalf("did not want an error, but got %v", err)
				}

				t.Fatalf("want error %s, but got %v", test.wantErr, err)
			}

			if test.wantErr != "" {
				t.Fatalf("want error %s, but got %v", test.wantErr, err)
			}

			var gotHeaders map[string][]string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotHeaders = r.Header
			}))
			defer srv.Close()

			client := http.Client{Transport: transport}

			_, err = client.Get(srv.URL)
			if err != nil {
				t.Fatalf("error making test server request: %+v", err)
			}

			assert.Equalf(t, test.wantHeaders, gotHeaders, "headers as expected")
		})
	}
}
