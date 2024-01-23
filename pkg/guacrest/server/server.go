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
	gen "github.com/guacsec/guac/pkg/guacrest/generated"
)

type DefaultServer struct{}

func (s *DefaultServer) HealthCheck(ctx context.Context, request gen.HealthCheckRequestObject) (gen.HealthCheckResponseObject, error) {
	return gen.HealthCheck200JSONResponse("Server is healthy"), nil
}

func (s *DefaultServer) AnalysisDependencies(ctx context.Context, request gen.AnalysisDependenciesRequestObject) (gen.AnalysisDependenciesResponseObject, error) {
	//return gen.AnalysisDependencies200JSONResponse{
	//  PurlListJSONResponse: []string{},
	//}, nil
	return nil, fmt.Errorf("Unimplemented")
}

func (s *DefaultServer) RetrieveDependencies(ctx context.Context, request gen.RetrieveDependenciesRequestObject) (gen.RetrieveDependenciesResponseObject, error) {
	//return gen.RetrieveDependencies200JSONResponse{
	//  PurlListJSONResponse: []string{},
	//}, nil
	return nil, fmt.Errorf("Unimplemented")
}
