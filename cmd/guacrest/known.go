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
	"fmt"
	"net/http"
	"strings"

	"github.com/guacsec/guac/internal/testing/ptrfrom"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"

	"github.com/Khan/genqlient/graphql"
	"github.com/gin-gonic/gin"
)

// This comment is for Swagger documentation
// @Summary Known artifact handler for artifact
// @Description Handles the known artifact based on the artifact
// @Tags Known
// @Accept  json
// @Produce  json
// @Param   artifact   path    string     true  "Artifact"
// @Success      200  {object}  Response
// @Failure      400  {object}  HTTPError
// @Failure      404  {object}  HTTPError
// @Failure      500  {object}  HTTPError
// @Router /known/artifact/{artifact} [get]
func artifactHandlerForArtifact(ctx context.Context) func(c *gin.Context) {
	return func(c *gin.Context) {
		graphqlEndpoint, err := parseKnownQueryParameters(c)
		if err != nil {
			c.JSON(http.StatusBadRequest, HTTPError{http.StatusBadRequest, fmt.Sprintf("error parsing query parameters: %v", err)})
			return
		}

		httpClient := &http.Client{Timeout: httpTimeout}
		gqlclient := graphql.NewClient(graphqlEndpoint, httpClient)

		artifact := strings.TrimLeft(c.Param("artifact"), "/") // Retrieve and trim the artifact from the URL parameter

		split := strings.Split(artifact, ":")
		if len(split) != 2 {
			c.JSON(http.StatusInternalServerError, HTTPError{http.StatusInternalServerError, "failed to parse artifact. Needs to be in algorithm:digest form"})
			return
		}
		artifactFilter := &model.ArtifactSpec{
			Algorithm: ptrfrom.String(strings.ToLower(split[0])),
			Digest:    ptrfrom.String(strings.ToLower(split[1])),
		}

		artifactResponse, err := model.Artifacts(ctx, gqlclient, *artifactFilter)
		if err != nil {
			c.JSON(http.StatusInternalServerError, HTTPError{http.StatusInternalServerError, fmt.Sprintf("error querying for artifacts: %v", err)})
			return
		}
		if len(artifactResponse.Artifacts) != 1 {
			c.JSON(http.StatusInternalServerError, HTTPError{http.StatusInternalServerError, "failed to located artifacts based on (algorithm:digest)"})
			return
		}
		artifactNeighbors, neighborsPath, err := queryKnownNeighbors(ctx, gqlclient, artifactResponse.Artifacts[0].Id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, HTTPError{http.StatusInternalServerError, fmt.Sprintf("error querying for artifact neighbors: %v", err)})
			return
		}

		path := append([]string{artifactResponse.Artifacts[0].Id}, neighborsPath...)

		response := Response{
			NeighborsData: artifactNeighbors,
			VisualizerURL: fmt.Sprintf("http://localhost:3000/?path=%v", strings.Join(removeDuplicateValuesFromPath(path), ",")),
		}
		c.IndentedJSON(200, response)
	}
}

// This comment is for Swagger documentation
// @Summary Known source handler for VCS
// @Description Handles the known source based on the VCS
// @Tags Known
// @Accept  json
// @Produce  json
// @Param   vcs   path    string     true  "VCS"
// @Success      200  {object}  Response
// @Failure      400  {object}  HTTPError
// @Failure      404  {object}  HTTPError
// @Failure      500  {object}  HTTPError
// @Router /known/source/{vcs} [get]
func sourceHandlerForVCS(ctx context.Context) func(c *gin.Context) {
	return func(c *gin.Context) {
		graphqlEndpoint, err := parseKnownQueryParameters(c)
		if err != nil {
			c.JSON(http.StatusBadRequest, HTTPError{http.StatusBadRequest, fmt.Sprintf("error parsing query parameters: %v", err)})
			return
		}

		httpClient := &http.Client{Timeout: httpTimeout}
		gqlclient := graphql.NewClient(graphqlEndpoint, httpClient)

		vcs := strings.TrimLeft(c.Param("vcs"), "/") // Retrieve and trim the vcs from the URL parameter

		srcInput, err := helpers.VcsToSrc(vcs)
		if err != nil {
			c.JSON(http.StatusBadRequest, HTTPError{http.StatusBadRequest, "invalid vcs"})
			return
		}

		srcFilter := &model.SourceSpec{
			Type:      &srcInput.Type,
			Namespace: &srcInput.Namespace,
			Name:      &srcInput.Name,
			Tag:       srcInput.Tag,
			Commit:    srcInput.Commit,
		}

		srcResponse, err := model.Sources(ctx, gqlclient, *srcFilter)
		if err != nil {
			c.JSON(http.StatusInternalServerError, HTTPError{http.StatusInternalServerError, fmt.Sprintf("Error querying source: %v", err)})
			return
		}

		if len(srcResponse.Sources) != 1 {
			c.JSON(http.StatusNotFound, HTTPError{http.StatusNotFound, "No source found for the given vcs"})
			return
		}

		sourceNeighbors, neighborsPath, err := queryKnownNeighbors(ctx, gqlclient, srcResponse.Sources[0].Namespaces[0].Names[0].Id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, HTTPError{http.StatusInternalServerError, fmt.Sprintf("Error querying for source Neighbors: %v", err)})
			return
		}

		path := append([]string{srcResponse.Sources[0].Namespaces[0].Names[0].Id,
			srcResponse.Sources[0].Namespaces[0].Id, srcResponse.Sources[0].Id}, neighborsPath...)

		response := Response{
			NeighborsData: sourceNeighbors,
			VisualizerURL: fmt.Sprintf("http://localhost:3000/?path=%v", strings.Join(removeDuplicateValuesFromPath(path), ",")),
		}
		c.IndentedJSON(200, response)
	}
}

// This comment is for Swagger documentation
// @Summary Known package handler for hash
// @Description Handles the known package based on the hash
// @Tags Known
// @Accept  json
// @Produce  json
// @Param   hash   path    string     true  "Hash"
// @Success      200  {object}  Response
// @Failure      400  {object}  HTTPError
// @Failure      404  {object}  HTTPError
// @Failure      500  {object}  HTTPError
// @Router /known/package/{hash} [get]
func packageHandlerForHash(ctx context.Context) func(c *gin.Context) {
	return func(c *gin.Context) {
		graphqlEndpoint, err := parseKnownQueryParameters(c)
		if err != nil {
			c.JSON(http.StatusBadRequest, HTTPError{http.StatusBadRequest, fmt.Sprintf("error parsing query parameters: %v", err)})
			return
		}

		httpClient := &http.Client{Timeout: httpTimeout}
		gqlclient := graphql.NewClient(graphqlEndpoint, httpClient)

		hash := strings.TrimLeft(c.Param("hash"), "/") // Retrieve and trim the hash from the URL parameter

		// Convert package URL to package input
		pkgInput, err := helpers.PurlToPkg(hash)
		if err != nil {
			c.JSON(http.StatusBadRequest, HTTPError{http.StatusBadRequest, "invalid hash"})
			return
		}

		pkgFilter := createPackageFilter(pkgInput)

		// Query for the package using the package filter
		pkgResponse, err := model.Packages(ctx, gqlclient, *pkgFilter)
		if err != nil {
			c.JSON(http.StatusInternalServerError, HTTPError{http.StatusInternalServerError, fmt.Sprintf("Error querying package: %v", err)})
			return
		}

		if len(pkgResponse.Packages) != 1 {
			c.JSON(http.StatusNotFound, HTTPError{http.StatusNotFound, "No package found for the given hash"})
			return
		}

		// Query for the package's neighbors
		res, path, err := queryNeighborsForPackage(ctx, gqlclient, pkgResponse.Packages[0])
		if err != nil {
			c.JSON(http.StatusInternalServerError, HTTPError{http.StatusInternalServerError, fmt.Sprintf("Error querying Neighbors: %v", err)})
			return
		}

		// Convert []*string to []string
		var pathStrings []string
		for _, s := range path {
			if s != nil {
				pathStrings = append(pathStrings, *s)
			}
		}

		response := Response{
			NeighborsData: res,
			VisualizerURL: fmt.Sprintf("http://localhost:3000/?path=%v", strings.Join(removeDuplicateValuesFromPath(pathStrings), ",")),
		}
		c.IndentedJSON(200, response)
	}
}

func parseKnownQueryParameters(c *gin.Context) (string, error) {
	graphqlEndpoint := c.Query("gql_addr")

	if graphqlEndpoint == "" {
		graphqlEndpoint = gqlDefaultServerURL
	}

	return graphqlEndpoint, nil
}

// createPackageFilter generates a package filter from a given package input.
// It constructs a package qualifier filter from the qualifiers in the package input,
// and returns a package specification with the type, namespace, name, version, subpath,
// and qualifiers from the package input.
func createPackageFilter(pkgInput *model.PkgInputSpec) *model.PkgSpec {
	pkgQualifierFilter := []model.PackageQualifierSpec{}
	for _, qualifier := range pkgInput.Qualifiers {
		pkgQualifierFilter = append(pkgQualifierFilter, model.PackageQualifierSpec{
			Key:   qualifier.Key,
			Value: &qualifier.Value,
		})
	}

	return &model.PkgSpec{
		Type:       &pkgInput.Type,
		Namespace:  pkgInput.Namespace,
		Name:       &pkgInput.Name,
		Version:    pkgInput.Version,
		Subpath:    pkgInput.Subpath,
		Qualifiers: pkgQualifierFilter,
	}
}

// queryNeighborsForPackage is a function that queries for the neighbors of a given package.
// It takes in a context, a graphql client, and a package model.
// It returns a slice of pointers to Neighbors and an error.
func queryNeighborsForPackage(ctx context.Context, gqlclient graphql.Client, pkg model.PackagesPackagesPackage) ([]*Neighbors, []*string, error) {
	var res []*Neighbors
	var path []*string

	// Query for the package's name neighbors
	pkgNameNeighbors, neighborsPath, err := queryKnownNeighbors(ctx, gqlclient, pkg.Namespaces[0].Names[0].Id)
	if err != nil {
		return nil, nil, err
	}

	res = append(res, pkgNameNeighbors)

	path = append(path, &pkg.Namespaces[0].Names[0].Id,
		&pkg.Namespaces[0].Id, &pkg.Id)

	for _, neighborPath := range neighborsPath {
		path = append(path, &neighborPath)
	}

	// Query for the package's version neighbors
	pkgNameNeighbors, _, err = queryKnownNeighbors(ctx, gqlclient, pkg.Namespaces[0].Names[0].Versions[0].Id)
	if err != nil {
		return nil, nil, err
	}

	res = append(res, pkgNameNeighbors)

	path = append(path, []*string{&pkg.Namespaces[0].Names[0].Versions[0].Id,
		&pkg.Namespaces[0].Names[0].Id, &pkg.Namespaces[0].Id, &pkg.Id}...)

	for _, neighborPath := range neighborsPath {
		path = append(path, &neighborPath)
	}

	return res, path, nil
}

type Neighbors struct {
	HashEquals   []*model.NeighborsNeighborsHashEqual           `json:",omitempty"`
	Scorecards   []*model.NeighborsNeighborsCertifyScorecard    `json:",omitempty"`
	Occurrences  []*model.NeighborsNeighborsIsOccurrence        `json:",omitempty"`
	HasSrcAt     []*model.NeighborsNeighborsHasSourceAt         `json:",omitempty"`
	HasSBOMs     []*model.NeighborsNeighborsHasSBOM             `json:",omitempty"`
	HasSLSAs     []*model.NeighborsNeighborsHasSLSA             `json:",omitempty"`
	CertifyVulns []*model.NeighborsNeighborsCertifyVuln         `json:",omitempty"`
	VexLinks     []*model.NeighborsNeighborsCertifyVEXStatement `json:",omitempty"`
	BadLinks     []*model.NeighborsNeighborsCertifyBad          `json:",omitempty"`
	GoodLinks    []*model.NeighborsNeighborsCertifyGood         `json:",omitempty"`
	PkgEquals    []*model.NeighborsNeighborsPkgEqual            `json:",omitempty"`
}

// queryKnownNeighbors is a function that queries for the neighbors of a given subject.
// It takes in a context, a graphql client, and a subject query ID.
// It returns a Neighbors struct and an error.
func queryKnownNeighbors(ctx context.Context, gqlclient graphql.Client, subjectQueryID string) (*Neighbors, []string, error) {
	collectedNeighbors := &Neighbors{}
	var path []string
	// Query for neighbors using the subject query ID
	neighborResponse, err := model.Neighbors(ctx, gqlclient, subjectQueryID, []model.Edge{})
	if err != nil {
		return nil, nil, fmt.Errorf("error querying Neighbors: %v", err)
	}
	for _, neighbor := range neighborResponse.Neighbors {
		switch v := neighbor.(type) {
		case *model.NeighborsNeighborsCertifyVuln:
			collectedNeighbors.CertifyVulns = append(collectedNeighbors.CertifyVulns, v)
			path = append(path, v.Id)
		case *model.NeighborsNeighborsCertifyBad:
			collectedNeighbors.BadLinks = append(collectedNeighbors.BadLinks, v)
			path = append(path, v.Id)
		case *model.NeighborsNeighborsCertifyGood:
			collectedNeighbors.GoodLinks = append(collectedNeighbors.GoodLinks, v)
			path = append(path, v.Id)
		case *model.NeighborsNeighborsCertifyScorecard:
			collectedNeighbors.Scorecards = append(collectedNeighbors.Scorecards, v)
			path = append(path, v.Id)
		case *model.NeighborsNeighborsCertifyVEXStatement:
			collectedNeighbors.VexLinks = append(collectedNeighbors.VexLinks, v)
			path = append(path, v.Id)
		case *model.NeighborsNeighborsHasSBOM:
			collectedNeighbors.HasSBOMs = append(collectedNeighbors.HasSBOMs, v)
			path = append(path, v.Id)
		case *model.NeighborsNeighborsHasSLSA:
			collectedNeighbors.HasSLSAs = append(collectedNeighbors.HasSLSAs, v)
			path = append(path, v.Id)
		case *model.NeighborsNeighborsHasSourceAt:
			collectedNeighbors.HasSrcAt = append(collectedNeighbors.HasSrcAt, v)
			path = append(path, v.Id)
		case *model.NeighborsNeighborsHashEqual:
			collectedNeighbors.HashEquals = append(collectedNeighbors.HashEquals, v)
			path = append(path, v.Id)
		case *model.NeighborsNeighborsIsOccurrence:
			collectedNeighbors.Occurrences = append(collectedNeighbors.Occurrences, v)
			path = append(path, v.Id)
		case *model.NeighborsNeighborsPkgEqual:
			collectedNeighbors.PkgEquals = append(collectedNeighbors.PkgEquals, v)
			path = append(path, v.Id)
		default:
			continue
		}
	}
	return collectedNeighbors, path, nil
}
