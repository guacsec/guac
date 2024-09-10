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

	"github.com/guacsec/guac/pkg/logging"

	"golang.org/x/time/rate"
	"google.golang.org/grpc"
)

// RateLimitedClient is a wrapper around grpc.ClientConn that adds rate limiting
// functionality to gRPC calls. It uses a rate.Limiter to control the rate of
// outgoing requests.
type RateLimitedClient struct {
	ClientConn *grpc.ClientConn
	Limiter    *rate.Limiter
}

// Invoke performs a gRPC call on the wrapped grpc.ClientConn, applying
// rate limiting before making the call. If the rate limit is exceeded, it waits
// until the limiter allows the request.
func (c *RateLimitedClient) Invoke(ctx context.Context, method string, args interface{}, reply interface{}, opts ...grpc.CallOption) error {
	logger := logging.FromContext(ctx)
	if !c.Limiter.Allow() {
		logger.Infof("Rate limit exceeded for method: %s", method)
		if err := c.Limiter.Wait(ctx); err != nil {
			return err
		}
	}
	return c.ClientConn.Invoke(ctx, method, args, reply, opts...)
}

// NewStream creates a new stream on the wrapped grpc.ClientConn, applying rate
// limiting before creating the stream. If the rate limit is exceeded, it waits
// until the limiter allows the request.
func (c *RateLimitedClient) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	logger := logging.FromContext(ctx)
	if !c.Limiter.Allow() {
		logger.Infof("Rate limit exceeded for method: %s", method)
		if err := c.Limiter.Wait(ctx); err != nil {
			return nil, err
		}
	}
	return c.ClientConn.NewStream(ctx, desc, method, opts...)
}

// NewRateLimitedClient creates a new RateLimitedClient that wraps the provided
// grpc.ClientConn and uses the provided rate.Limiter to control the rate of
// outgoing requests. It returns a grpc.ClientConnInterface that can be used
// wherever a grpc.ClientConn is expected.
//
// Parameters:
//   - conn: The underlying grpc.ClientConn to wrap. This is typically an instance
//     of grpc.ClientConn created using grpc.NewClient or any custom implementation of
//     grpc.ClientConnInterface.
//   - limiter: The rate.Limiter to use for controlling the rate of outgoing requests.
func NewRateLimitedClient(conn *grpc.ClientConn, limiter *rate.Limiter) grpc.ClientConnInterface {
	return &RateLimitedClient{
		ClientConn: conn,
		Limiter:    limiter,
	}
}
