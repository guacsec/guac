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
	"maps"
	"slices"

	"github.com/Khan/genqlient/graphql"
	gql "github.com/guacsec/guac/pkg/assembler/clients/generated"
	assembler_helpers "github.com/guacsec/guac/pkg/assembler/helpers"
	gen "github.com/guacsec/guac/pkg/guacrest/generated"
	"github.com/guacsec/guac/pkg/guacrest/helpers"
	"github.com/guacsec/guac/pkg/logging"
)

// GetVulnsForArtifact returns the vulnerabilities certified against every
// package reachable from the artifact identified by digest.
func GetVulnsForArtifact(ctx context.Context, gqlClient graphql.Client, digest string) ([]gen.Vulnerability, error) {
	art, err := helpers.FindArtifactWithDigest(ctx, gqlClient, digest)
	if err != nil {
		return nil, fmt.Errorf("failed to find artifact: %w", err)
	}
	pkgIDs, err := packageIDsForArtifact(ctx, gqlClient, &art)
	if err != nil {
		return nil, err
	}
	return vulnsForPackageIDs(ctx, gqlClient, pkgIDs)
}

// GetVulnsForPackage returns the vulnerabilities certified against the
// package identified by purl. When includeDependencies is true the returned
// list also contains vulnerabilities certified against any transitive
// dependency of that package.
func GetVulnsForPackage(ctx context.Context, gqlClient graphql.Client, purl string, includeDependencies bool) ([]gen.Vulnerability, error) {
	pkg, err := helpers.FindPackageWithPurl(ctx, gqlClient, purl)
	if err != nil {
		return nil, fmt.Errorf("failed to find package: %w", err)
	}
	pkgIDs := []string{pkg.Id}
	if includeDependencies {
		deps, err := GetDepsForPackage(ctx, gqlClient, purl)
		if err != nil {
			return nil, fmt.Errorf("failed to get dependencies: %w", err)
		}
		for depID := range deps {
			if depID == pkg.Id {
				continue
			}
			pkgIDs = append(pkgIDs, depID)
		}
		// deps is a map, so sort the dependency IDs to keep the response order
		// stable across identical requests; the purl's own vulns stay first.
		slices.Sort(pkgIDs[1:])
	}
	return vulnsForPackageIDs(ctx, gqlClient, pkgIDs)
}

// packageIDsForArtifact returns the sorted IDs of every package version the
// byDigest walk reaches, equivalents included - unlike GetDepsForArtifact.
func packageIDsForArtifact(ctx context.Context, gqlClient graphql.Client, art *gql.AllArtifactTree) ([]string, error) {
	reachable, _, err := getReachableNodes(ctx, art, newByDigest(gqlClient))
	if err != nil {
		return nil, err
	}
	// reachable is keyed by node ID, so the result is already de-duplicated.
	pkgIDs := pkgVersionIDs(ctx, maps.Values(reachable))
	// Map iteration order is randomized, so sort to keep the vulnerability
	// order stable across identical requests.
	slices.Sort(pkgIDs)
	return pkgIDs, nil
}

// vulnsForPackageIDs queries CertifyVuln for each package version ID and
// flattens the results into the REST Vulnerability shape, deduplicating by
// certification ID.
func vulnsForPackageIDs(ctx context.Context, gqlClient graphql.Client, pkgIDs []string) ([]gen.Vulnerability, error) {
	logger := logging.FromContext(ctx)
	// A novuln record certifies that a scan found nothing, so it is not a
	// vulnerability - unfiltered, every clean package reports one.
	noVuln := false
	seen := map[string]struct{}{}
	result := []gen.Vulnerability{}
	for _, id := range pkgIDs {
		resp, err := gql.CertifyVuln(ctx, gqlClient, gql.CertifyVulnSpec{
			Package:       &gql.PkgSpec{Id: &id},
			Vulnerability: &gql.VulnerabilitySpec{NoVuln: &noVuln},
		})
		if err != nil {
			logger.Errorf("CertifyVuln query returned err: %v", err)
			return nil, helpers.Err502
		}
		for _, cv := range resp.GetCertifyVuln() {
			if _, dup := seen[cv.Id]; dup {
				continue
			}
			seen[cv.Id] = struct{}{}
			result = append(result, certifyVulnToREST(cv))
		}
	}
	return result, nil
}

// certifyVulnToREST projects a gql CertifyVuln into the REST Vulnerability
// shape defined by the OpenAPI spec.
func certifyVulnToREST(cv gql.CertifyVulnCertifyVuln) gen.Vulnerability {
	pkgTree := cv.Package.AllPkgTree
	purl := assembler_helpers.AllPkgTreeToPurl(&pkgTree)

	ids := make([]string, 0, len(cv.Vulnerability.VulnerabilityIDs))
	for _, vid := range cv.Vulnerability.VulnerabilityIDs {
		ids = append(ids, vid.VulnerabilityID)
	}

	vulnType := cv.Vulnerability.Type
	dbURI := cv.Metadata.DbUri
	dbVer := cv.Metadata.DbVersion
	scannerURI := cv.Metadata.ScannerUri
	scannerVer := cv.Metadata.ScannerVersion
	origin := cv.Metadata.Origin
	collector := cv.Metadata.Collector
	timeScanned := cv.Metadata.TimeScanned

	return gen.Vulnerability{
		Package: purl,
		Vulnerability: gen.VulnerabilityDetails{
			Type:             &vulnType,
			VulnerabilityIDs: ids,
		},
		Metadata: gen.ScanMetadata{
			DbUri:          &dbURI,
			DbVersion:      &dbVer,
			ScannerUri:     &scannerURI,
			ScannerVersion: &scannerVer,
			Origin:         &origin,
			Collector:      &collector,
			TimeScanned:    &timeScanned,
		},
	}
}
