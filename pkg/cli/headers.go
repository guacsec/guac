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
	"os"

	"github.com/ProtonMail/gluon/rfc822"
	"github.com/guacsec/guac/pkg/logging"
)

type httpHeaderTransport struct {
	extraHeaders map[string][]string
	http.RoundTripper
}

func HTTPHeaderTransport(ctx context.Context, filename string, transport http.RoundTripper) http.RoundTripper {
	if filename == "" {
		return transport
	}

	logger := logging.FromContext(ctx)

	b, err := os.ReadFile(filename)
	if err != nil {
		logger.Fatalf("error reading header file: %v", err)
	}

	rh, err := rfc822.NewHeader(b)
	if err != nil {
		logger.Fatalf("error parsing header file: %v", err)
	}

	h := make(map[string][]string)
	rh.Entries(func(k, v string) {
		h[k] = append(h[k], v)
	})

	return &httpHeaderTransport{h, transport}
}

func (t *httpHeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	for k, vs := range t.extraHeaders {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}

	return t.RoundTripper.RoundTrip(req)
}
