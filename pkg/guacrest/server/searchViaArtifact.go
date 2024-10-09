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
	"github.com/Khan/genqlient/graphql"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	gen "github.com/guacsec/guac/pkg/guacrest/generated"
	"github.com/guacsec/guac/pkg/guacrest/helpers"
)

type dfsNode struct {
	expanded bool
	depth    int
	purl     string
}

// searchVulnerabilitiesViaArtifact searches for vulnerabilities associated with the given artifact.
//
// This function utilizes the searchDependenciesByArtifact function to traverse the dependencies
// of the specified artifact. It then fetches and returns vulnerabilities for each discovered package.
//
// Parameters:
// - ctx: The context for the operation, used for cancellation and deadlines.
// - gqlClient: The GraphQL client used for querying the database.
// - artifactSpec: The specification of the artifact from which to start the search.
// - searchSoftware: A boolean flag indicating whether to include software components in the search.
//
// Returns:
// - A slice of Vulnerability objects containing the found vulnerabilities.
// - An error, if any occurs during the search or data retrieval.
func searchVulnerabilitiesViaArtifact(ctx context.Context, gqlClient graphql.Client, artifactSpec model.ArtifactSpec, searchSoftware bool, startSBOM model.AllHasSBOMTree) ([]gen.Vulnerability, error) {
	var vulnerabilities []gen.Vulnerability

	// Map to track processed vulnerabilities
	processedVulns := make(map[string]bool)

	nodeMap, queue, err := searchDependenciesByArtifact(ctx, gqlClient, artifactSpec, searchSoftware, startSBOM)
	if err != nil {
		return nil, err
	}

	for len(queue) > 0 {
		pkgID := queue[0]
		queue = queue[1:]
		nowNode := nodeMap[pkgID]

		// Avoid cycles.
		if nowNode.expanded {
			continue
		}

		// Fetch vulnerabilities for the current package
		certVulns, err := model.CertifyVuln(ctx, gqlClient, model.CertifyVulnSpec{
			Package: &model.PkgSpec{
				Id: &pkgID,
			},
		})
		if err != nil {
			continue
		}

		for _, certifyVuln := range certVulns.CertifyVuln {
			if certifyVuln.Vulnerability.Type == "novuln" {
				continue // Skip 'novuln' entries
			}
			if len(certifyVuln.Vulnerability.VulnerabilityIDs) == 0 {
				continue // Skip if no vulnerability IDs
			}

			purl := certifyVuln.Package.Namespaces[0].Names[0].Versions[0].Purl

			// Collect non-empty vulnerability IDs
			for _, vID := range certifyVuln.Vulnerability.VulnerabilityIDs {
				if vID.VulnerabilityID != "" {
					// Create a unique key combining PURL and vulnerability ID
					vulnKey := purl + "_" + vID.VulnerabilityID

					// Check if we've already processed this vulnerability for this package
					if processedVulns[vulnKey] {
						continue // Skip duplicates
					}

					// Mark this vulnerability as processed
					processedVulns[vulnKey] = true

					// Build the vulnerability object
					v := gen.Vulnerability{
						Metadata: gen.ScanMetadata{
							Collector:      &certifyVuln.Metadata.Collector,
							DbUri:          &certifyVuln.Metadata.DbUri,
							DbVersion:      &certifyVuln.Metadata.DbVersion,
							Origin:         &certifyVuln.Metadata.Origin,
							ScannerUri:     &certifyVuln.Metadata.ScannerUri,
							ScannerVersion: &certifyVuln.Metadata.ScannerVersion,
							TimeScanned:    &certifyVuln.Metadata.TimeScanned,
						},
						Packages: []string{purl},
						Vulnerability: gen.VulnerabilityDetails{
							Type:             &certifyVuln.Vulnerability.Type,
							VulnerabilityIDs: []string{vID.VulnerabilityID},
						},
					}

					vulnerabilities = append(vulnerabilities, v)
				}
			}
		}

		// Mark node as expanded.
		nowNode.expanded = true
		nodeMap[pkgID] = nowNode
	}

	return vulnerabilities, nil
}

// searchDependenciesByArtifact traverses the dependency graph starting from a given artifact.
// This function searches all dependencies or just dependencies in the given sbom.
//
// Parameters:
// - ctx: The context for the operation, used for cancellation and deadlines.
// - gqlClient: The GraphQL client used for querying the database.
// - artifactSpec: The specification of the artifact from which to start the dependency traversal.
// - searchSoftware: A boolean flag indicating whether to search via software components while traversing.
//
// Returns:
// - A map of package IDs to dfsNode structures representing the traversal state.
// - A queue of package IDs for further processing.
// - A map to track processed vulnerabilities to avoid duplicates.
// - An error, if any occurs during the traversal or data retrieval.
func searchDependenciesByArtifact(ctx context.Context, gqlClient graphql.Client, artifactSpec model.ArtifactSpec, searchSoftware bool, startSBOM model.AllHasSBOMTree) (map[string]dfsNode, []string, error) {
	hasSBOMs, err := model.HasSBOMs(ctx, gqlClient, model.HasSBOMSpec{
		Subject: &model.PackageOrArtifactSpec{
			Artifact: &artifactSpec,
		},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("error fetching hasSBOMs for artifact: %w", err)
	}

	nodeMap := make(map[string]dfsNode)
	queue := []string{}

	if searchSoftware {
		hasSBOMs = &model.HasSBOMsResponse{
			HasSBOM: []model.HasSBOMsHasSBOM{
				{
					AllHasSBOMTree: startSBOM,
				},
			},
		}
	}

	if !searchSoftware {
		for _, hasSBOM := range hasSBOMs.HasSBOM {
			for _, includedDep := range hasSBOM.IncludedDependencies {
				pkg := includedDep.DependencyPackage
				pkgID := pkg.Namespaces[0].Names[0].Versions[0].Id
				purl := pkg.Namespaces[0].Names[0].Versions[0].Purl
				nodeMap[pkgID] = dfsNode{depth: 1, purl: purl}
				queue = append(queue, pkgID)
			}
		}
	} else {
		for _, hasSbom := range hasSBOMs.HasSBOM {
			for _, software := range hasSbom.IncludedSoftware {
				switch s := software.(type) {
				case *model.AllHasSBOMTreeIncludedSoftwarePackage:
					pkgID := s.Namespaces[0].Names[0].Versions[0].Id
					purl := s.Namespaces[0].Names[0].Versions[0].Purl
					nodeMap[pkgID] = dfsNode{depth: 1, purl: purl}
					queue = append(queue, pkgID)
				case *model.AllHasSBOMTreeIncludedSoftwareArtifact:
					// convert artifact to pkg, then use the pkg id to get the vulnerability
					pkg, err := helpers.GetPkgFromArtifact(gqlClient, s.Id)
					if err != nil {
						return nil, nil, fmt.Errorf("failed to get package attached to artifact %s: %w", s.Id, err)
					}
					pkgID := pkg.Namespaces[0].Names[0].Versions[0].Id
					purl := pkg.Namespaces[0].Names[0].Versions[0].Purl
					nodeMap[pkgID] = dfsNode{depth: 1, purl: purl}
					queue = append(queue, pkgID)
				}
			}
		}
	}

	return nodeMap, queue, nil
}
