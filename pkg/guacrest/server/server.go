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
	helpers2 "github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/guacrest/helpers"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Khan/genqlient/graphql"
	"github.com/guacsec/guac/pkg/dependencies"
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
	switch request.Params.Sort {
	case gen.Frequency:
		packages, err := dependencies.GetDependenciesBySortedDependentCnt(ctx, s.gqlClient)
		if err != nil {
			return gen.AnalyzeDependencies500JSONResponse{
				InternalServerErrorJSONResponse: gen.InternalServerErrorJSONResponse{
					Message: err.Error(),
				},
			}, nil
		}

		var packageNames []gen.PackageName

		for _, p := range packages {
			pac := p // have to do this because we don't want packageNames to keep on appending a pointer of the same variable p.
			packageNames = append(packageNames, gen.PackageName{
				Name:           pac.Name,
				DependentCount: pac.DependentCount,
			})
		}

		val := gen.AnalyzeDependencies200JSONResponse{
			PackageNameListJSONResponse: packageNames,
		}

		return val, nil
	case gen.Scorecard:
		return nil, fmt.Errorf("scorecard sort is unimplemented")
	default:
		return nil, fmt.Errorf("%v sort is unsupported", request.Params.Sort)
	}
}

func (s *DefaultServer) GetPackageInfo(ctx context.Context, request gen.GetPackageInfoRequestObject) (gen.GetPackageInfoResponseObject, error) {
	decodedPurl, err := url.QueryUnescape(request.Purl)
	if err != nil {
		return gen.GetPackageInfo400JSONResponse{
			BadRequestJSONResponse: gen.BadRequestJSONResponse{
				Message: fmt.Sprintf("Invalid PURL: %v", err),
			},
		}, nil
	}

	// Add the "pkg:" prefix if not present
	if !strings.HasPrefix(decodedPurl, "pkg:") {
		decodedPurl = "pkg:" + decodedPurl
	}

	pkgInput, err := helpers2.PurlToPkg(decodedPurl)
	if err != nil {
		return gen.GetPackageInfo400JSONResponse{
			BadRequestJSONResponse: gen.BadRequestJSONResponse{
				Message: fmt.Sprintf("Failed to parse PURL: %v", err),
			},
		}, nil
	}

	packageResponse, err := helpers.GetInfoForPackage(ctx, s.gqlClient, pkgInput, request.Params.Vulns)
	if err != nil {
		return nil, err
	}

	response := gen.GetPackageInfo200JSONResponse{
		PackageInfoResponseJSONResponse: *packageResponse,
	}

	// Create a custom pretty-printed response
	return &helpers.PrettyJSONResponse{Data: response}, nil
}
