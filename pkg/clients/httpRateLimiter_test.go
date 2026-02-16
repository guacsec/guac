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

//go:build integration

package clients

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/guacsec/guac/pkg/logging"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/time/rate"
)

// TestRateLimitedTransport tests the RateLimitedTransport functionality.
func TestRateLimitedTransport(t *testing.T) {
	// Set up the logger
	var logBuffer bytes.Buffer
	encoderConfig := zap.NewProductionEncoderConfig()
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderConfig),
		zapcore.AddSync(&logBuffer),
		zap.DebugLevel,
	)
	logger := zap.New(core).Sugar()

	ctx := context.Background()
	ctx = context.WithValue(ctx, logging.ChildLoggerKey, logger)

	// Set up a test HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer func() { _ = server.Close() }()

	// Create a rate limiter that allows 10 requests per 10 seconds
	limiter := rate.NewLimiter(rate.Every(time.Second*10), 10)

	// Create a RateLimitedTransport
	transport := NewRateLimitedTransport(http.DefaultTransport, limiter)

	// Create an HTTP client with the RateLimitedTransport
	client := &http.Client{Transport: transport}

	logBuffer.Reset()

	// Make 11 requests to test rate limiting
	for i := 0; i < 11; i++ {
		req, err := http.NewRequestWithContext(ctx, "GET", server.URL, nil)
		assert.NoError(t, err)

		resp, err := client.Do(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		_ = resp.Body.Close()
	}

	logOutput := logBuffer.String()

	// Check if the log contains the rate limit exceeded message
	assert.Contains(t, logOutput, "Rate limit exceeded")
}
