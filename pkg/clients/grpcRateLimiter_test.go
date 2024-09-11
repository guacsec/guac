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
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

func TestUnaryClientInterceptor_RateLimitExceeded(t *testing.T) {
	// Set up the rate limiter to allow only 1 request per second
	limiter := NewLimiter(1)

	// Create the unary client interceptor with the rate limiter
	interceptor := UnaryClientInterceptor(limiter)

	// Mock a gRPC request
	ctx := context.Background()
	method := "/test.service/method"
	req := struct{}{}
	reply := struct{}{}
	cc := &grpc.ClientConn{}

	// Mock invoker function
	invoker := func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		return nil // Success if called
	}

	// First request should pass through without hitting the rate limit
	err := interceptor(ctx, method, req, reply, cc, invoker)
	assert.NoError(t, err, "first request should succeed")

	// Immediately attempt another request, which should be rate-limited
	err = interceptor(ctx, method, req, reply, cc, invoker)
	assert.NoError(t, err, "second request should succeed")
}

func TestUnaryClientInterceptor_NoRateLimit(t *testing.T) {
	// Set up the rate limiter to allow many requests per second
	limiter := NewLimiter(1000)

	// Create the unary client interceptor with the rate limiter
	interceptor := UnaryClientInterceptor(limiter)

	// Mock a gRPC request
	ctx := context.Background()
	method := "/test.service/method"
	req := struct{}{}
	reply := struct{}{}
	cc := &grpc.ClientConn{}

	// Mock invoker function
	invoker := func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		return nil // Success if called
	}

	// Multiple requests should pass through without hitting the rate limit
	for i := 0; i < 5; i++ {
		err := interceptor(ctx, method, req, reply, cc, invoker)
		assert.NoError(t, err, "request should succeed")
	}
}

func TestUnaryClientInterceptor_RespectRateLimit(t *testing.T) {
	// Set up the rate limiter to allow only 1 request per second
	limiter := NewLimiter(1)

	// Create the unary client interceptor with the rate limiter
	interceptor := UnaryClientInterceptor(limiter)

	// Mock a gRPC request
	ctx := context.Background()
	method := "/test.service/method"
	req := struct{}{}
	reply := struct{}{}
	cc := &grpc.ClientConn{}

	// Mock invoker function
	invoker := func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		return nil // Success if called
	}

	// First request should pass
	err := interceptor(ctx, method, req, reply, cc, invoker)
	assert.NoError(t, err, "first request should succeed")

	// Wait for 1 second to allow the rate limiter to reset
	time.Sleep(1 * time.Second)

	// The second request should also pass after rate limit reset
	err = interceptor(ctx, method, req, reply, cc, invoker)
	assert.NoError(t, err, "second request should succeed after waiting for rate limit reset")
}
