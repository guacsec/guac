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

	gen "github.com/guacsec/guac/pkg/guacrest/generated"
	"github.com/guacsec/guac/pkg/guacrest/helpers"
)

// Maps helpers.Err502 and helpers.Err500 to the corresponding OpenAPI response type.
// Other errors are returned as Client errors.
func handleErr(ctx context.Context, err error) gen.RetrieveDependenciesResponseObject {
	if err == nil {
		return nil
	}
	switch err {
	case helpers.Err502:
		return gen.RetrieveDependencies502JSONResponse{
			BadGatewayJSONResponse: gen.BadGatewayJSONResponse{
				Message: err.Error(),
			}}
	case helpers.Err500:
		return gen.RetrieveDependencies500JSONResponse{
			InternalServerErrorJSONResponse: gen.InternalServerErrorJSONResponse{
				Message: err.Error(),
			}}
	default:
		return gen.RetrieveDependencies400JSONResponse{
			BadRequestJSONResponse: gen.BadRequestJSONResponse{
				Message: err.Error(),
			}}
	}
}
