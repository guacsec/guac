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
	"github.com/guacsec/guac/pkg/version"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type RateLimitedClient struct {
	ClientConn *grpc.ClientConn
	Limiter    *rate.Limiter
}

func (c *RateLimitedClient) Invoke(ctx context.Context, method string, args interface{}, reply interface{}, opts ...grpc.CallOption) error {
	logger := logging.FromContext(ctx)
	if !c.Limiter.Allow() {
		logger.Debugf("Rate limit exceeded for method: %s", method)
		if err := c.Limiter.Wait(ctx); err != nil {
			return err
		}
	}
	md := metadata.Pairs("user-agent", version.UserAgent)
	ctx = metadata.NewOutgoingContext(ctx, md)
	return c.ClientConn.Invoke(ctx, method, args, reply, opts...)
}

func (c *RateLimitedClient) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	logger := logging.FromContext(ctx)
	if !c.Limiter.Allow() {
		logger.Debugf("Rate limit exceeded for method: %s", method)
		if err := c.Limiter.Wait(ctx); err != nil {
			return nil, err
		}
	}
	md := metadata.Pairs("user-agent", version.UserAgent)
	ctx = metadata.NewOutgoingContext(ctx, md)
	return c.ClientConn.NewStream(ctx, desc, method, opts...)
}

func NewRateLimitedClient(conn *grpc.ClientConn, limiter *rate.Limiter) grpc.ClientConnInterface {
	return &RateLimitedClient{
		ClientConn: conn,
		Limiter:    limiter,
	}
}
