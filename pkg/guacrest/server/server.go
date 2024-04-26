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

package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/Khan/genqlient/graphql"
	gen "github.com/guacsec/guac/pkg/guacrest/generated"
	"github.com/guacsec/guac/pkg/logging"
)

// DefaultServer implements the API, backed by the GraphQL Server
type DefaultServer struct {
	gqlClient graphql.Client
}

func NewDefaultServer(gqlClient graphql.Client) *DefaultServer {
	return &DefaultServer{gqlClient: gqlClient}
}

// Adds the logger to the http request context
func AddLoggerToCtxMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		newCtx := logging.WithLogger(r.Context())
		newReq := r.WithContext(newCtx)
		next.ServeHTTP(w, newReq)
	})
}

// Logs data for a request and its response. The request context should already contain
// the logger.
func LogRequestsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		newCtx := logging.WithLogger(r.Context(),
			"method", r.Method,
			"path", r.URL.Path,
		)
		newReq := r.WithContext(newCtx)
		next.ServeHTTP(w, newReq)

		logger := logging.FromContext(newReq.Context())
		logger.Infow("Request handled successfully", "latency", time.Since(start))
	})
}

func (s *DefaultServer) HealthCheck(ctx context.Context, request gen.HealthCheckRequestObject) (gen.HealthCheckResponseObject, error) {
	return gen.HealthCheck200JSONResponse("Server is healthy"), nil
}

func (s *DefaultServer) AnalyzeDependencies(ctx context.Context, request gen.AnalyzeDependenciesRequestObject) (gen.AnalyzeDependenciesResponseObject, error) {
	return nil, fmt.Errorf("Unimplemented")
}

func (s *DefaultServer) RetrieveDependencies(ctx context.Context, request gen.RetrieveDependenciesRequestObject) (gen.RetrieveDependenciesResponseObject, error) {
	return nil, fmt.Errorf("Unimplemented")
}
