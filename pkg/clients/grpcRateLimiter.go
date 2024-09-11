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

	grpc_ratelimit "github.com/grpc-ecosystem/go-grpc-middleware/ratelimit"
	"github.com/guacsec/guac/pkg/logging"
	"go.uber.org/ratelimit"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type limiter struct {
	ratelimit.Limiter
}

// Limit blocks to ensure that RPS is met
func (l *limiter) Limit() bool {
	l.Take()
	return false
}

// NewLimiter return new go-grpc Limiter, specified the number of requests you want to limit as a counts per second.
func NewLimiter(count int) grpc_ratelimit.Limiter {
	return &limiter{
		Limiter: ratelimit.New(count),
	}
}

// UnaryClientInterceptor return server unary interceptor that limit requests.
func UnaryClientInterceptor(limiter grpc_ratelimit.Limiter) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		logger := logging.FromContext(ctx)
		if limiter.Limit() {
			logger.Infof("Rate limit exceeded for method: %s", method)
			return status.Errorf(codes.ResourceExhausted, "%s have been rejected by rate limiting.", method)
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}
