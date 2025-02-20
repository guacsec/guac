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
	"net/http"

	gen "github.com/guacsec/guac/pkg/guacrest/generated"
	"github.com/guacsec/guac/pkg/guacrest/helpers"
)

// Define a custom type for endpoint types
type EndpointType int

const (
	GetPackagePurls EndpointType = iota
	GetPackageVulns
	GetPackageDeps
	GetArtifactVulns
	GetArtifactDeps
)

// IsErrorResponse checks if the response status code indicates an error.
func IsErrorResponse(statusCode int) bool {
	return statusCode >= 400
}

// IsSuccessResponse checks if the response status code indicates success.
func IsSuccessResponse(statusCode int) bool {
	return statusCode == http.StatusOK
}

func handleErr(
	ctx context.Context,
	err error,
	endpointType EndpointType,
) interface{} {
	if err == nil {
		return createBadRequestResponse(endpointType, "Unknown error")
	}
	switch err {
	case helpers.Err502:
		return createBadGatewayResponse(endpointType, err.Error())
	case helpers.Err500:
		return createInternalServerErrorResponse(endpointType, err.Error())
	default:
		return createBadRequestResponse(endpointType, err.Error())
	}
}

func createBadRequestResponse(endpointType EndpointType, message string) interface{} {
	switch endpointType {
	case GetPackagePurls:
		return gen.GetPackagePurls400JSONResponse{
			BadRequestJSONResponse: gen.BadRequestJSONResponse{
				Message: message,
			},
		}
	case GetPackageDeps:
		return gen.GetPackageDeps400JSONResponse{
			BadRequestJSONResponse: gen.BadRequestJSONResponse{
				Message: message,
			},
		}
	case GetPackageVulns:
		return gen.GetPackageVulns400JSONResponse{
			BadRequestJSONResponse: gen.BadRequestJSONResponse{
				Message: message,
			},
		}
	case GetArtifactDeps:
		return gen.GetArtifactDeps400JSONResponse{
			BadRequestJSONResponse: gen.BadRequestJSONResponse{
				Message: message,
			},
		}
	case GetArtifactVulns:
		return gen.GetArtifactVulns400JSONResponse{
			BadRequestJSONResponse: gen.BadRequestJSONResponse{
				Message: message,
			},
		}
	default:
		return nil
	}
}

func createInternalServerErrorResponse(endpointType EndpointType, message string) interface{} {
	switch endpointType {
	case GetPackagePurls:
		return gen.GetPackagePurls500JSONResponse{
			InternalServerErrorJSONResponse: gen.InternalServerErrorJSONResponse{
				Message: message,
			},
		}
	case GetPackageDeps:
		return gen.GetPackageDeps500JSONResponse{
			InternalServerErrorJSONResponse: gen.InternalServerErrorJSONResponse{
				Message: message,
			},
		}
	case GetPackageVulns:
		return gen.GetPackageVulns500JSONResponse{
			InternalServerErrorJSONResponse: gen.InternalServerErrorJSONResponse{
				Message: message,
			},
		}
	case GetArtifactDeps:
		return gen.GetArtifactDeps500JSONResponse{
			InternalServerErrorJSONResponse: gen.InternalServerErrorJSONResponse{
				Message: message,
			},
		}
	case GetArtifactVulns:
		return gen.GetArtifactVulns500JSONResponse{
			InternalServerErrorJSONResponse: gen.InternalServerErrorJSONResponse{
				Message: message,
			},
		}
	default:
		return nil
	}
}

func createBadGatewayResponse(endpointType EndpointType, message string) interface{} {
	switch endpointType {
	case GetPackagePurls:
		return gen.GetPackagePurls502JSONResponse{
			BadGatewayJSONResponse: gen.BadGatewayJSONResponse{
				Message: message,
			},
		}
	case GetPackageDeps:
		return gen.GetPackageDeps502JSONResponse{
			BadGatewayJSONResponse: gen.BadGatewayJSONResponse{
				Message: message,
			},
		}
	case GetPackageVulns:
		return gen.GetPackageVulns502JSONResponse{
			BadGatewayJSONResponse: gen.BadGatewayJSONResponse{
				Message: message,
			},
		}
	case GetArtifactDeps:
		return gen.GetArtifactDeps502JSONResponse{
			BadGatewayJSONResponse: gen.BadGatewayJSONResponse{
				Message: message,
			},
		}
	case GetArtifactVulns:
		return gen.GetArtifactVulns502JSONResponse{
			BadGatewayJSONResponse: gen.BadGatewayJSONResponse{
				Message: message,
			},
		}
	default:
		return nil
	}
}
