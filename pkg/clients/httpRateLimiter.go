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
	"context"
	"github.com/guacsec/guac/pkg/version"
	"golang.org/x/time/rate"
	"net/http"
	"time"
)

var (
	osvDevLimiter         = rate.NewLimiter(rate.Every(time.Minute/10000), 10000)
	clearlyDefinedLimiter = rate.NewLimiter(rate.Every(time.Minute/2000), 2000)
)

type RateLimitedTransport struct {
	Transport http.RoundTripper
	Limiter   *rate.Limiter
}

func (t *RateLimitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	err := t.Limiter.Wait(req.Context())
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", version.UserAgent)
	return t.Transport.RoundTrip(req)
}

func NewOsvDevClient(ctx context.Context) *http.Client {
	return &http.Client{
		Transport: &RateLimitedTransport{
			Transport: http.DefaultTransport,
			Limiter:   osvDevLimiter,
		},
	}
}

// This will be implemented once ClearlyDefined is implemented
//func NewClearlyDefinedClient(ctx context.Context) *http.Client {
//	return &http.Client{
//		Transport: &RateLimitedTransport{
//			Transport: http.DefaultTransport,
//			Limiter:   clearlyDefinedLimiter,
//		},
//	}
//}
