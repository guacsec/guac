//
// Copyright 2023 The GUAC Authors.
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

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/Khan/genqlient/graphql"
	"github.com/gin-gonic/gin"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
)

// badHandler is a function that returns a gin.HandlerFunc. It handles requests to the /bad endpoint.
func badHandler(ctx context.Context) func(c *gin.Context) {
	return func(c *gin.Context) {
		graphqlEndpoint, searchDepth, err := parseBadQueryParameters(c)

		if err != nil {
			c.String(http.StatusBadRequest, err.Error())
			return
		}

		httpClient := &http.Client{Timeout: httpTimeout}
		gqlclient := graphql.NewClient(graphqlEndpoint, httpClient)

		certifyBadResponse, err := model.CertifyBads(ctx, gqlclient, model.CertifyBadSpec{})
		if err != nil {
			c.String(http.StatusInternalServerError, "error querying for package: %v", err)
			return
		}

		// Iterate over the bad certifications.
		for _, certifyBad := range certifyBadResponse.CertifyBad {
			// Handle the different types of subjects.
			switch subject := certifyBad.Subject.(type) {
			case *model.AllCertifyBadSubjectPackage:
				var path []string

				var pkgVersions []model.AllPkgTreeNamespacesPackageNamespaceNamesPackageNameVersionsPackageVersion
				if len(subject.Namespaces[0].Names[0].Versions) == 0 {
					pkgFilter := &model.PkgSpec{
						Type:      &subject.Type,
						Namespace: &subject.Namespaces[0].Namespace,
						Name:      &subject.Namespaces[0].Names[0].Name,
					}
					pkgResponse, err := model.Packages(ctx, gqlclient, *pkgFilter)
					if err != nil {
						c.String(http.StatusInternalServerError, "error querying for package: %v", err)
						return
					}
					if len(pkgResponse.Packages) != 1 {
						c.String(http.StatusInternalServerError, "failed to located package based on package from certifyBad")
						return
					}
					pkgVersions = pkgResponse.Packages[0].Namespaces[0].Names[0].Versions
				} else {
					pkgVersions = subject.Namespaces[0].Names[0].Versions
				}

				pkgPath, err := searchDependencyPackagesReverse(ctx, gqlclient, "", pkgVersions[0].Id, searchDepth)
				if err != nil {
					c.String(http.StatusInternalServerError, "error searching dependency packages match: %v", err)
					return
				}

				if len(pkgPath) > 0 {
					for _, version := range pkgVersions {
						path = append([]string{certifyBad.Id,
							version.Id,
							subject.Namespaces[0].Names[0].Id, subject.Namespaces[0].Id,
							subject.Id}, pkgPath...)
					}

					c.JSON(http.StatusOK, gin.H{
						"Visualizer url": fmt.Sprintf("http://localhost:3000/?path=%v", strings.Join(removeDuplicateValuesFromPath(path), `,`)),
					})
				} else {
					c.String(http.StatusNotFound, "No paths to bad package found!\n")
				}
			case *model.AllCertifyBadSubjectSource:
				var path []string
				srcFilter := &model.SourceSpec{
					Type:      &subject.Type,
					Namespace: &subject.Namespaces[0].Namespace,
					Name:      &subject.Namespaces[0].Names[0].Name,
					Tag:       subject.Namespaces[0].Names[0].Tag,
					Commit:    subject.Namespaces[0].Names[0].Commit,
				}
				srcResponse, err := model.Sources(ctx, gqlclient, *srcFilter)
				if err != nil {
					c.String(http.StatusInternalServerError, "error querying for sources: %v", err)
					return
				}
				if len(srcResponse.Sources) != 1 {
					c.String(http.StatusInternalServerError, "failed to located sources based on vcs")
					return
				}

				neighborResponse, err := model.Neighbors(ctx, gqlclient, srcResponse.Sources[0].Namespaces[0].Names[0].Id, []model.Edge{model.EdgeSourceHasSourceAt, model.EdgeSourceIsOccurrence})
				if err != nil {
					c.String(http.StatusInternalServerError, "error querying neighbors: %v", err)
					return
				}
				for _, neighbor := range neighborResponse.Neighbors {
					switch v := neighbor.(type) {
					case *model.NeighborsNeighborsHasSourceAt:
						if len(v.Package.Namespaces[0].Names[0].Versions) > 0 {
							path = append(path, v.Id, v.Package.Namespaces[0].Names[0].Versions[0].Id, v.Package.Namespaces[0].Names[0].Id, v.Package.Namespaces[0].Id, v.Package.Id)
						} else {
							path = append(path, v.Id, v.Package.Namespaces[0].Names[0].Id, v.Package.Namespaces[0].Id, v.Package.Id)
						}
					case *model.NeighborsNeighborsIsOccurrence:
						path = append(path, v.Id, v.Artifact.Id)
					default:
						continue
					}
				}

				if len(path) > 0 {
					fullCertifyBadPath := append([]string{certifyBad.Id,
						subject.Namespaces[0].Names[0].Id,
						subject.Namespaces[0].Id, subject.Id}, path...)
					path = append(path, fullCertifyBadPath...)
					c.JSON(http.StatusOK, gin.H{
						"Visualizer url": fmt.Sprintf("http://localhost:3000/?path=%v", strings.Join(removeDuplicateValuesFromPath(path), `,`)),
					})
				} else {
					c.String(http.StatusNotFound, "No paths to bad source found!\n")
				}

			case *model.AllCertifyBadSubjectArtifact:
				var path []string
				artifactFilter := &model.ArtifactSpec{
					Algorithm: &subject.Algorithm,
					Digest:    &subject.Digest,
				}

				artifactResponse, err := model.Artifacts(ctx, gqlclient, *artifactFilter)
				if err != nil {
					c.String(http.StatusInternalServerError, "error querying for artifacts: %v", err)
					return
				}
				if len(artifactResponse.Artifacts) != 1 {
					c.String(http.StatusInternalServerError, "failed to located artifacts based on (algorithm:digest)")
					return
				}
				neighborResponse, err := model.Neighbors(ctx, gqlclient, artifactResponse.Artifacts[0].Id, []model.Edge{model.EdgeArtifactHashEqual, model.EdgeArtifactIsOccurrence})
				if err != nil {
					c.String(http.StatusInternalServerError, "error querying neighbors: %v", err)
					return
				}
				for _, neighbor := range neighborResponse.Neighbors {
					switch v := neighbor.(type) {
					case *model.NeighborsNeighborsHashEqual:
						path = append(path, v.Id)
					case *model.NeighborsNeighborsIsOccurrence:
						switch occurrenceSubject := v.Subject.(type) {
						case *model.AllIsOccurrencesTreeSubjectPackage:
							path = append(path, v.Id, occurrenceSubject.Namespaces[0].Names[0].Versions[0].Id, occurrenceSubject.Namespaces[0].Names[0].Id, occurrenceSubject.Namespaces[0].Id, occurrenceSubject.Id)
						case *model.AllIsOccurrencesTreeSubjectSource:
							path = append(path, v.Id, occurrenceSubject.Namespaces[0].Names[0].Id, occurrenceSubject.Namespaces[0].Id, occurrenceSubject.Id)
						}
					default:
						continue
					}
				}

				if len(path) > 0 {
					path = append(path, append([]string{certifyBad.Id, subject.Id}, path...)...)
					c.JSON(http.StatusOK, gin.H{
						"Visualizer url": fmt.Sprintf("http://localhost:3000/?path=%v", strings.Join(removeDuplicateValuesFromPath(path), `,`)),
					})
				} else {
					c.String(http.StatusNotFound, "No paths to bad artifact found!\n")
				}
			}
		}
	}
}

// parseBadQueryParameters is a helper function that parses the query parameters from a request.
func parseBadQueryParameters(c *gin.Context) (string, int, error) {
	graphqlEndpoint := c.Query("gql_addr")

	if graphqlEndpoint == "" {
		graphqlEndpoint = gqlDefaultServerURL
	}

	var searchDepth int
	var err error

	// Parse the search depth from the query parameters.
	searchDepthString := c.Query("search_depth")
	if searchDepthString != "" {
		searchDepth, err = strconv.Atoi(searchDepthString)
		if err != nil && searchDepthString != "" {
			// If the search depth is not an integer, return an error.
			return "", 0, errors.New("invalid search depth")
		}
	}

	return graphqlEndpoint, searchDepth, nil
}
