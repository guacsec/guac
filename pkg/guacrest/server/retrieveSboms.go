//
// Copyright 2026 The GUAC Authors.
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
	"sort"

	"github.com/Khan/genqlient/graphql"
	gql "github.com/guacsec/guac/pkg/assembler/clients/generated"
	assembler_helpers "github.com/guacsec/guac/pkg/assembler/helpers"
	gen "github.com/guacsec/guac/pkg/guacrest/generated"
	"github.com/guacsec/guac/pkg/guacrest/helpers"
	"github.com/guacsec/guac/pkg/logging"
)

// RetrieveSboms retrieves HasSBOM records from GraphQL, filters them optionally
// by package purl, and returns them sorted by knownSince descending (with id tiebreaker).
func RetrieveSboms(ctx context.Context, gqlClient graphql.Client, packageFilter *string) ([]gen.Sbom, error) {
	logger := logging.FromContext(ctx)

	var matchingSet map[string]struct{}
	if packageFilter != nil {
		matchingPurls, err := FindMatchingPurls(ctx, gqlClient, *packageFilter)
		if err != nil {
			return nil, err
		}
		if len(matchingPurls) == 0 {
			return []gen.Sbom{}, nil
		}
		matchingSet = make(map[string]struct{}, len(matchingPurls))
		for _, p := range matchingPurls {
			matchingSet[p] = struct{}{}
		}
	}

	response, err := gql.HasSBOMs(ctx, gqlClient, gql.HasSBOMSpec{})
	if err != nil {
		logger.Errorf("HasSBOMs query returned error: %v", err)
		return nil, helpers.Err502
	}
	if response == nil {
		logger.Errorf("HasSBOMs query returned nil response")
		return nil, helpers.Err500
	}

	sboms := make([]gen.Sbom, 0, len(response.GetHasSBOM()))
	for _, rawSbom := range response.GetHasSBOM() {
		if packageFilter != nil {
			if !sbomMatches(rawSbom, matchingSet) {
				continue
			}
		}

		subject, ok := sbomSubjectToREST(rawSbom.GetSubject())
		if !ok {
			logger.Warnf("Skipping HasSBOM %s with unhandled subject type: %T", rawSbom.GetId(), rawSbom.GetSubject())
			continue
		}

		dl := rawSbom.GetDownloadLocation()
		origin := rawSbom.GetOrigin()
		collector := rawSbom.GetCollector()
		docRef := rawSbom.GetDocumentRef()

		sboms = append(sboms, gen.Sbom{
			Id:               rawSbom.GetId(),
			Subject:          subject,
			Uri:              rawSbom.GetUri(),
			Algorithm:        rawSbom.GetAlgorithm(),
			Digest:           rawSbom.GetDigest(),
			DownloadLocation: &dl,
			KnownSince:       rawSbom.GetKnownSince(),
			Origin:           &origin,
			Collector:        &collector,
			DocumentRef:      &docRef,
		})
	}

	sort.SliceStable(sboms, func(i, j int) bool {
		if !sboms[i].KnownSince.Equal(sboms[j].KnownSince) {
			return sboms[i].KnownSince.After(sboms[j].KnownSince)
		}
		return sboms[i].Id < sboms[j].Id
	})

	return sboms, nil
}

func sbomMatches(sbom gql.HasSBOMsHasSBOM, matchingSet map[string]struct{}) bool {
	if pkg, ok := sbom.GetSubject().(*gql.AllHasSBOMTreeSubjectPackage); ok {
		for _, p := range getPackagePurls(pkg.AllPkgTree) {
			if _, exists := matchingSet[p]; exists {
				return true
			}
		}
	}

	for _, sw := range sbom.GetIncludedSoftware() {
		if swPkg, ok := sw.(*gql.AllHasSBOMTreeIncludedSoftwarePackage); ok {
			for _, p := range getPackagePurls(swPkg.AllPkgTree) {
				if _, exists := matchingSet[p]; exists {
					return true
				}
			}
		}
	}

	return false
}

func sbomSubjectToREST(sub gql.AllHasSBOMTreeSubjectPackageOrArtifact) (gen.SbomSubject, bool) {
	switch s := sub.(type) {
	case *gql.AllHasSBOMTreeSubjectPackage:
		purl := packagePurl(s.AllPkgTree)
		return gen.SbomSubject{
			Type: gen.Package,
			Purl: &purl,
		}, true
	case *gql.AllHasSBOMTreeSubjectArtifact:
		artStr := fmt.Sprintf("%s:%s", s.Algorithm, s.Digest)
		return gen.SbomSubject{
			Type:     gen.Artifact,
			Artifact: &artStr,
		}, true
	default:
		return gen.SbomSubject{}, false
	}
}

func packagePurl(pkgTree gql.AllPkgTree) string {
	versions := helpers.GetVersionsOfAllPackageTree(pkgTree)
	if len(versions) > 0 && versions[0].Purl != "" {
		return versions[0].Purl
	}
	if len(pkgTree.Namespaces) > 0 && len(pkgTree.Namespaces[0].Names) > 0 {
		return assembler_helpers.AllPkgTreeToPurl(&pkgTree)
	}
	return ""
}

func getPackagePurls(pkgTree gql.AllPkgTree) []string {
	var purls []string
	versions := helpers.GetVersionsOfAllPackageTree(pkgTree)
	for _, v := range versions {
		if v.Purl != "" {
			purls = append(purls, v.Purl)
		}
	}
	if len(purls) == 0 {
		if p := packagePurl(pkgTree); p != "" {
			purls = append(purls, p)
		}
	}
	return purls
}
