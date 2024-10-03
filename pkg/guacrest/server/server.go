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
	"net/url"
	"strings"
	"time"

	model "github.com/guacsec/guac/pkg/assembler/clients/generated"

	helpers2 "github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/guacrest/helpers"

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

		var packageNames []gen.AnalyzeDependenciesPackageName

		for _, p := range packages {
			pac := p // have to do this because we don't want packageNames to keep on appending a pointer of the same variable p.
			packageNames = append(packageNames, gen.AnalyzeDependenciesPackageName{
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

func (s *DefaultServer) GetPackagePurlsByPurl(ctx context.Context, request gen.GetPackagePurlsByPurlRequestObject) (gen.GetPackagePurlsByPurlResponseObject, error) {
	purl, err := url.QueryUnescape(request.Purl)
	if err != nil {
		return gen.GetPackagePurlsByPurl400JSONResponse{
			BadRequestJSONResponse: gen.BadRequestJSONResponse{
				Message: fmt.Sprintf("Failed to unencode purl: %v", err),
			},
		}, nil
	}

	// Convert the PURL string to a PkgInputSpec
	pkgInput, err := helpers2.PurlToPkg(purl)
	if err != nil {
		return gen.GetPackagePurlsByPurl400JSONResponse{
			BadRequestJSONResponse: gen.BadRequestJSONResponse{
				Message: fmt.Sprintf("Failed to parse PURL: %v", err),
			},
		}, nil
	}

	pkgSpec := helpers.ConvertPkgInputSpecToPkgSpec(pkgInput)

	// Retrieve package information using the helper function
	purls, _, err := helpers.GetPurlsForPkg(ctx, s.gqlClient, pkgSpec)
	if err != nil {
		return gen.GetPackagePurlsByPurl500JSONResponse{
			InternalServerErrorJSONResponse: gen.InternalServerErrorJSONResponse{
				Message: fmt.Sprintf("Error retrieving package info: %v", err),
			},
		}, nil
	}

	result := gen.GetPackagePurlsByPurl200JSONResponse{}
	result = append(result, purls...)

	// Return the successful response with the retrieved package information
	return result, nil
}

func (s *DefaultServer) GetPackageVulnerabilitiesByPurl(ctx context.Context, request gen.GetPackageVulnerabilitiesByPurlRequestObject) (gen.GetPackageVulnerabilitiesByPurlResponseObject, error) {
	purl, err := url.QueryUnescape(request.Purl)
	if err != nil {
		return gen.GetPackageVulnerabilitiesByPurl400JSONResponse{
			BadRequestJSONResponse: gen.BadRequestJSONResponse{
				Message: fmt.Sprintf("Failed to unencode purl: %v", err),
			},
		}, nil
	}

	// Convert the PURL string to a PkgInputSpec
	pkgInput, err := helpers2.PurlToPkg(purl)
	if err != nil {
		return gen.GetPackageVulnerabilitiesByPurl400JSONResponse{
			BadRequestJSONResponse: gen.BadRequestJSONResponse{
				Message: fmt.Sprintf("Failed to parse PURL: %v", err),
			},
		}, nil
	}

	pkgSpec := helpers.ConvertPkgInputSpecToPkgSpec(pkgInput)

	// Retrieve package information using the helper function
	_, packageIDs, err := helpers.GetPurlsForPkg(ctx, s.gqlClient, pkgSpec)
	if err != nil {
		return gen.GetPackageVulnerabilitiesByPurl500JSONResponse{
			InternalServerErrorJSONResponse: gen.InternalServerErrorJSONResponse{
				Message: fmt.Sprintf("Error retrieving package info: %v", err),
			},
		}, nil
	}

	latestSbom := &model.AllHasSBOMTree{}
	shouldSearchSoftware := false

	// If the LatestSBOM query is specified then all other queries should be for the latest SBOM
	if request.Params.LatestSBOM != nil && *request.Params.LatestSBOM {
		latestSbom, err = helpers.LatestSBOMFromID(ctx, s.gqlClient, packageIDs)
		if err != nil {
			return nil, err
		}
		shouldSearchSoftware = true
	}

	vulns, err := helpers.SearchPkgForVulns(ctx, s.gqlClient, pkgSpec, shouldSearchSoftware, *latestSbom)
	if err != nil {
		return gen.GetPackageVulnerabilitiesByPurl500JSONResponse{
			InternalServerErrorJSONResponse: gen.InternalServerErrorJSONResponse{
				Message: fmt.Sprintf("Error retrieving vulnerabilities for package: %v", err),
			},
		}, nil
	}

	result := gen.GetPackageVulnerabilitiesByPurl200JSONResponse{
		VulnerabilityListJSONResponse: vulns,
	}

	// Return the successful response with the retrieved package information
	return result, nil
}

func (s *DefaultServer) GetPackageDependenciesByPurl(ctx context.Context, request gen.GetPackageDependenciesByPurlRequestObject) (gen.GetPackageDependenciesByPurlResponseObject, error) {
	purl, err := url.QueryUnescape(request.Purl)
	if err != nil {
		return gen.GetPackageDependenciesByPurl400JSONResponse{
			BadRequestJSONResponse: gen.BadRequestJSONResponse{
				Message: fmt.Sprintf("Failed to unencode purl: %v", err),
			},
		}, nil
	}

	// Convert the PURL string to a PkgInputSpec
	pkgInput, err := helpers2.PurlToPkg(purl)
	if err != nil {
		return gen.GetPackageDependenciesByPurl400JSONResponse{
			BadRequestJSONResponse: gen.BadRequestJSONResponse{
				Message: fmt.Sprintf("Failed to parse PURL: %v", err),
			},
		}, nil
	}

	pkgSpec := helpers.ConvertPkgInputSpecToPkgSpec(pkgInput)

	// Retrieve package IDs
	_, packageIDs, err := helpers.GetPurlsForPkg(ctx, s.gqlClient, pkgSpec)
	if err != nil {
		return gen.GetPackageDependenciesByPurl500JSONResponse{
			InternalServerErrorJSONResponse: gen.InternalServerErrorJSONResponse{
				Message: fmt.Sprintf("Error retrieving package info: %v", err),
			},
		}, nil
	}

	latestSbom := &model.AllHasSBOMTree{}
	shouldSearchSoftware := false

	// If 'latestSBOM' is true, retrieve the latest SBOM
	if request.Params.LatestSBOM != nil && *request.Params.LatestSBOM {
		latestSbom, err = helpers.LatestSBOMFromID(ctx, s.gqlClient, packageIDs)
		if err != nil {
			return gen.GetPackageDependenciesByPurl500JSONResponse{
				InternalServerErrorJSONResponse: gen.InternalServerErrorJSONResponse{
					Message: fmt.Sprintf("Error retrieving latest SBOM: %v", err),
				},
			}, nil
		}
		shouldSearchSoftware = true
	}

	// Use the searchDependencies function to retrieve dependencies
	dependencies, err := helpers.SearchDependencies(ctx, s.gqlClient, pkgSpec, shouldSearchSoftware, *latestSbom)
	if err != nil {
		return gen.GetPackageDependenciesByPurl500JSONResponse{
			InternalServerErrorJSONResponse: gen.InternalServerErrorJSONResponse{
				Message: fmt.Sprintf("Error retrieving dependencies: %v", err),
			},
		}, nil
	}

	result := gen.GetPackageDependenciesByPurl200JSONResponse{}

	for _, depPurl := range dependencies {
		result.DependencyListJSONResponse = append(result.DependencyListJSONResponse, depPurl)
	}

	return result, nil
}

func (s *DefaultServer) GetArtifactVulnerabilities(ctx context.Context, request gen.GetArtifactVulnerabilitiesRequestObject) (gen.GetArtifactVulnerabilitiesResponseObject, error) {
	artifactStr, err := url.QueryUnescape(request.Artifact)
	if err != nil {
		return gen.GetArtifactVulnerabilities400JSONResponse{
			BadRequestJSONResponse: gen.BadRequestJSONResponse{
				Message: fmt.Sprintf("Failed to unencode artifact: %v", err),
			},
		}, nil
	}

	logger := logging.FromContext(ctx)
	logger.Infof("artifact: %s", artifactStr)

	// Parse the artifact string into an ArtifactSpec
	parts := strings.SplitN(artifactStr, ":", 2)
	if len(parts) != 2 {
		return gen.GetArtifactVulnerabilities400JSONResponse{
			BadRequestJSONResponse: gen.BadRequestJSONResponse{
				Message: fmt.Sprintf("Invalid artifact format: %s", artifactStr),
			},
		}, nil
	}
	algorithm := parts[0]
	digest := parts[1]

	artifactSpec := model.ArtifactSpec{
		Algorithm: &algorithm,
		Digest:    &digest,
	}

	// Call the helper function to search for vulnerabilities
	vulnerabilities, err := helpers.SearchVulnerabilitiesByArtifact(ctx, s.gqlClient, artifactSpec, false)
	if err != nil {
		logging.FromContext(ctx).Errorf("Error retrieving vulnerabilities: %v", err)
		return gen.GetArtifactVulnerabilities500JSONResponse{
			InternalServerErrorJSONResponse: gen.InternalServerErrorJSONResponse{
				Message: fmt.Sprintf("Error retrieving vulnerabilities: %v", err),
			},
		}, nil
	}

	result := gen.GetArtifactVulnerabilities200JSONResponse{}
	result.VulnerabilityListJSONResponse = append(result.VulnerabilityListJSONResponse, vulnerabilities...)

	// Return the list of vulnerabilities
	return result, nil
}

//func (s *DefaultServer) getArtifactInfo(ctx context.Context, request gen.GetArtifactInfoRequestObject) (gen.GetArtifactInfoResponseObject, error) {
//	artifact := request.Artifact
//	splitString := strings.Split(artifact, ":")
//
//	occurrence, err := model.Occurrences(ctx, s.gqlClient, model.IsOccurrenceSpec{
//		Artifact: &model.ArtifactSpec{
//			Algorithm: &splitString[0],
//			Digest:    &splitString[1],
//		},
//	})
//	if err != nil {
//		return gen.GetArtifactInfo400JSONResponse{
//			BadRequestJSONResponse: gen.BadRequestJSONResponse{
//				Message: fmt.Sprintf("Invalid identifier, artifact should be comprised of <algorithm>:<digest>: %v", artifact),
//			},
//		}, nil
//	}
//
//	convertedOccurrence, ok := occurrence.IsOccurrence[0].Subject.(*model.AllIsOccurrencesTreeSubjectPackage)
//	if !ok {
//		return gen.GetArtifactInfo500JSONResponse{
//			InternalServerErrorJSONResponse: gen.InternalServerErrorJSONResponse{
//				Message: fmt.Sprintf("Error converting issoccurrence to model.IsOccurrencesTreeSubjectPackage: %v", artifact),
//			},
//		}, nil
//	}
//
//	result := gen.GetArtifactInfo200JSONResponse{}
//	//result = append(result, purls...)
//
//	// Return the successful response with the retrieved package information
//	return result, nil
//}

//func (s *DefaultServer) GetPackageInfo(ctx context.Context, request gen.GetPackageInfoRequestObject) (gen.GetPackageInfoResponseObject, error) {
//	logger := logging.FromContext(ctx)
//
//	decodedPurlOrArtifact, err := url.QueryUnescape(request.PurlOrArtifact)
//	if err != nil {
//		logger.Infof("error decoding purl or artifact: %v", err)
//		return gen.GetPackageInfo400JSONResponse{
//			BadRequestJSONResponse: gen.BadRequestJSONResponse{
//				Message: fmt.Sprintf("Invalid identifier: %v", err),
//			},
//		}, nil
//	}
//
//	// Determine if the identifier is a PURL or an artifact
//	var pkgInput *model.PkgInputSpec
//
//	if strings.HasPrefix(decodedPurlOrArtifact, "pkg:") {
//		pkgInput, err = helpers2.PurlToPkg(decodedPurlOrArtifact)
//		if err != nil {
//			return gen.GetPackageInfo400JSONResponse{
//				BadRequestJSONResponse: gen.BadRequestJSONResponse{
//					Message: fmt.Sprintf("Failed to parse PURL: %v", err),
//				},
//			}, nil
//		}
//	} else {
//		splitString := strings.Split(decodedPurlOrArtifact, ":")
//
//		if len(splitString) != 2 {
//			return gen.GetPackageInfo400JSONResponse{
//				BadRequestJSONResponse: gen.BadRequestJSONResponse{
//					Message: fmt.Sprintf("Invalid identifier, artifact should be comprised of <algorithm>:<digest>: %v", decodedPurlOrArtifact),
//				},
//			}, nil
//		}
//
//		occurrence, err := model.Occurrences(ctx, s.gqlClient, model.IsOccurrenceSpec{
//			Artifact: &model.ArtifactSpec{
//				Algorithm: &splitString[0],
//				Digest:    &splitString[1],
//			},
//		})
//		if err != nil {
//			return gen.GetPackageInfo400JSONResponse{
//				BadRequestJSONResponse: gen.BadRequestJSONResponse{
//					Message: fmt.Sprintf("Invalid identifier, artifact should be comprised of <algorithm>:<digest>: %v", decodedPurlOrArtifact),
//				},
//			}, nil
//		}
//
//		convertedOccurrence, ok := occurrence.IsOccurrence[0].Subject.(*model.AllIsOccurrencesTreeSubjectPackage)
//		if !ok {
//			return gen.GetPackageInfo500JSONResponse{
//				InternalServerErrorJSONResponse: gen.InternalServerErrorJSONResponse{
//					Message: fmt.Sprintf("Error converting issoccurrence to model.IsOccurrencesTreeSubjectPackage: %v", decodedPurlOrArtifact),
//				},
//			}, nil
//		}
//
//		pkg := convertedOccurrence.AllPkgTree
//
//		pkgInput = &model.PkgInputSpec{
//			Type:      pkg.Type,
//			Namespace: &pkg.Namespaces[0].Namespace,
//			Name:      pkg.Namespaces[0].Names[0].Name,
//			Version:   &pkg.Namespaces[0].Names[0].Versions[0].Version,
//			Subpath:   &pkg.Namespaces[0].Names[0].Versions[0].Subpath,
//		}
//	}
//
//	// whatToSearch states what type of query we want to run for the given package or artifact
//	var whatToSearch helpers.QueryType
//
//	if request.Params.Query != nil {
//		for _, queryParam := range *request.Params.Query {
//			switch queryParam {
//			case gen.Dependencies:
//				whatToSearch.Dependencies = true
//			case gen.Vulns:
//				whatToSearch.Vulns = true
//			case gen.LatestSbom:
//				whatToSearch.LatestSBOM = true
//			}
//		}
//	}
//
//	packageResponse, err := helpers.GetInfoForPackage(ctx, s.gqlClient, pkgInput, whatToSearch)
//	if err != nil {
//		return gen.GetPackageInfo400JSONResponse{
//			BadRequestJSONResponse: gen.BadRequestJSONResponse{
//				Message: fmt.Sprintf("error getting package info: %v", err),
//			},
//		}, nil
//	}
//
//	response := gen.GetPackageInfo200JSONResponse{
//		PackageInfoResponseJSONResponse: *packageResponse,
//	}
//
//	// Create a custom pretty-printed response
//	return &helpers.PrettyJSONResponse{Data: response}, nil
//}
