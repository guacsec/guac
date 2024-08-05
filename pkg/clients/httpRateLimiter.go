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

package clients

import (
	"golang.org/x/time/rate"
	"net/http"

	"github.com/guacsec/guac/pkg/logging"
	"github.com/guacsec/guac/pkg/version"
)

// RateLimitedTransport is a wrapper around http.RoundTripper that adds rate
// limiting functionality to HTTP requests. It uses a rate.Limiter to control
// the rate of outgoing requests.
type RateLimitedTransport struct {
	Transport http.RoundTripper
	Limiter   *rate.Limiter
}

// RoundTrip executes a single HTTP transaction on the wrapped http.RoundTripper,
// applying rate limiting before making the request. If the rate limit is exceeded,
// it waits until the limiter allows the request.
func (t *RateLimitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	logger := logging.FromContext(req.Context())
	if !t.Limiter.Allow() {
		logger.Debugf("Rate limit exceeded")
		if err := t.Limiter.Wait(req.Context()); err != nil {
			return nil, err
		}
	}
	req.Header.Set("User-Agent", version.UserAgent)
	return t.Transport.RoundTrip(req)
}

// NewRateLimitedTransport creates a new RateLimitedTransport that wraps the provided
// http.RoundTripper and uses the provided rate.Limiter to control the rate of
// outgoing requests. It returns an http.RoundTripper that can be used wherever
// an http.RoundTripper is expected.
//
// Parameters:
//   - transport: The underlying http.RoundTripper to wrap. This is typically an
//     instance of http.Transport or any custom implementation of http.RoundTripper.
//   - limiter: The rate.Limiter to use for controlling the rate of outgoing requests.
func NewRateLimitedTransport(transport http.RoundTripper, limiter *rate.Limiter) http.RoundTripper {
	return &RateLimitedTransport{
		Transport: transport,
		Limiter:   limiter,
	}
}
