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

func artifactHandlerForArtifact(ctx context.Context) func(c *gin.Context) {
	return func(c *gin.Context) {
		httpClient := &http.Client{Timeout: httpTimeout}
		gqlclient := graphql.NewClient(gqlServerURL, httpClient)

		artifact := strings.TrimLeft(c.Param("artifact"), "/") // Retrieve and trim the artifact from the URL parameter

		split := strings.Split(artifact, ":")
		if len(split) != 2 {
			c.String(http.StatusInternalServerError, "failed to parse artifact. Needs to be in algorithm:digest form")
			return
		}
		artifactFilter := &model.ArtifactSpec{
			Algorithm: ptrfrom.String(strings.ToLower(string(split[0]))),
			Digest:    ptrfrom.String(strings.ToLower(string(split[1]))),
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
		artifactNeighbors, _, err := queryKnownNeighbors(ctx, gqlclient, artifactResponse.Artifacts[0].Id)
		if err != nil {
			c.String(http.StatusInternalServerError, "error querying for artifact neighbors: %v", err)
			return
		}

		c.IndentedJSON(200, JsonResponse{NeighborsData: []*Neighbors{artifactNeighbors}})
	}
}

func sourceHandlerForVCS(ctx context.Context) func(c *gin.Context) {
	return func(c *gin.Context) {
		httpClient := &http.Client{Timeout: httpTimeout}
		gqlclient := graphql.NewClient(gqlServerURL, httpClient)

		vcs := strings.TrimLeft(c.Param("vcs"), "/") // Retrieve and trim the vcs from the URL parameter

		srcInput, err := helpers.VcsToSrc(vcs)
		if err != nil {
			c.String(400, "invalid vcs")
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
			c.String(500, "Error querying source: %v", err)
			return
		}

		if len(srcResponse.Sources) != 1 {
			c.String(404, "No source found for the given vcs")
			return
		}

		sourceNeighbors, _, err := queryKnownNeighbors(ctx, gqlclient, srcResponse.Sources[0].Namespaces[0].Names[0].Id)
		if err != nil {
			c.String(500, "Error querying for source Neighbors: %v", err)
			return
		}

		c.IndentedJSON(200, JsonResponse{NeighborsData: []*Neighbors{sourceNeighbors}})
	}
}

func packageHandlerForHash(ctx context.Context) func(c *gin.Context) {
	return func(c *gin.Context) {
		httpClient := &http.Client{Timeout: httpTimeout}
		gqlclient := graphql.NewClient(gqlServerURL, httpClient)

		hash := strings.TrimLeft(c.Param("hash"), "/") // Retrieve and trim the hash from the URL parameter

		// Convert package URL to package input
		pkgInput, err := helpers.PurlToPkg(hash)
		if err != nil {
			c.String(400, "invalid hash")
			return
		}

		pkgFilter := createPackageFilter(pkgInput)

		// Query for the package
		pkgResponse, err := model.Packages(ctx, gqlclient, *pkgFilter)
		if err != nil {
			c.String(500, "Error querying package: %v", err)
			return
		}

		if len(pkgResponse.Packages) != 1 {
			c.String(404, "No package found for the given hash")
			return
		}

		// Query for the package's neighbors
		res, err := queryNeighborsForPackage(ctx, gqlclient, pkgResponse.Packages[0])
		if err != nil {
			c.String(500, "Error querying Neighbors: %v", err)
			return
		}

		c.IndentedJSON(200, JsonResponse{NeighborsData: res})
	}
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
func queryNeighborsForPackage(ctx context.Context, gqlclient graphql.Client, pkg model.PackagesPackagesPackage) ([]*Neighbors, error) {
	var res []*Neighbors

	pkgNameNeighbors, _, err := queryKnownNeighbors(ctx, gqlclient, pkg.Namespaces[0].Names[0].Id)
	if err != nil {
		return nil, err
	}
	res = append(res, pkgNameNeighbors)

	pkgNameNeighbors, _, err = queryKnownNeighbors(ctx, gqlclient, pkg.Namespaces[0].Names[0].Versions[0].Id)
	if err != nil {
		return nil, err
	}
	res = append(res, pkgNameNeighbors)

	return res, nil
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

// JsonResponse represents the JSON response structure.
type JsonResponse struct {
	NeighborsData []*Neighbors `json:"neighborsData"`
}

func queryKnownNeighbors(ctx context.Context, gqlclient graphql.Client, subjectQueryID string) (*Neighbors, []string, error) {
	collectedNeighbors := &Neighbors{}
	var path []string
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
