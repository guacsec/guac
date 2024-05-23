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
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/guacsec/guac/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestHTTPHeaderTransport(t *testing.T) {
	type test struct {
		name        string
		headerFile  string
		wantErr     any
		wantHeaders map[string][]string
	}

	tests := []test{
		{
			name:       "creating a header transport with a non-existent file results in an error",
			headerFile: "does-not-exist.txt",
			wantErr:    "error reading header file: open does-not-exist.txt: no such file or directory",
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
			// The zap.WithFatalHook value WriteThenPanic makes it so that instead of
			// exiting on .Fatal() calls, the logger panics. You can recover from these
			// panics in a goroutine, and this makes it possible to test such cases.
			logging.InitLogger(logging.Debug, zap.WithFatalHook(zapcore.WriteThenPanic))
			ctx := logging.WithLogger(context.Background())

			var transport http.RoundTripper
			recovered := make(chan any)
			finished := false

			go func() {
				defer func() {
					recovered <- recover()
				}()

				transport = HTTPHeaderTransport(ctx, test.headerFile, http.DefaultTransport)

				finished = true
			}()

			require.Equal(t, test.wantErr, <-recovered, "fatal error message")

			if test.wantErr != nil {
				assert.False(t, finished, "call did not finish")
				return
			}

			assert.True(t, finished, "call finished")

			var gotHeaders map[string][]string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotHeaders = r.Header
			}))
			defer srv.Close()

			client := http.Client{Transport: transport}

			_, err := client.Get(srv.URL)
			if err != nil {
				t.Fatalf("error making test server request: %+v", err)
			}

			assert.Equalf(t, test.wantHeaders, gotHeaders, "headers")
		})
	}
}
