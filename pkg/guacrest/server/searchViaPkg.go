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

// searchVulnerabilitiesViaPkg searches for vulnerabilities associated with the given package
// and its dependencies.
//
// Parameters:
// - ctx: The context for the operation
// - gqlClient: The GraphQL client used for querying
// - pkgSpec: The package specification to start the search from
//
// Returns:
// - A slice of Vulnerability objects containing the found vulnerabilities
// - An error
//
// The function performs a breadth-first search starting from the given package,
// collecting vulnerabilities for each package and its dependencies.
func searchVulnerabilitiesViaPkg(ctx context.Context, gqlClient graphql.Client, pkgSpec model.PkgSpec, searchSoftware bool, startSBOM model.AllHasSBOMTree) ([]gen.Vulnerability, error) {
	var vulnerabilities []gen.Vulnerability

	pkgs, err := searchDependencies(ctx, gqlClient, pkgSpec, searchSoftware, startSBOM)
	if err != nil {
		return nil, fmt.Errorf("error searching dependencies: %w", err)
	}

	for pkg := range pkgs {
		vulns, err := model.CertifyVuln(ctx, gqlClient, model.CertifyVulnSpec{
			Package: &model.PkgSpec{
				Id: &pkg,
			},
		})
		if err != nil {
			return nil, fmt.Errorf("error fetching vulnerabilities from package spec: %w", err)
		}

		for _, vuln := range vulns.CertifyVuln {
			vulnerability := gen.Vulnerability{
				Metadata: gen.ScanMetadata{
					Collector:      &vuln.Metadata.Collector,
					DbUri:          &vuln.Metadata.DbUri,
					DbVersion:      &vuln.Metadata.DbVersion,
					Origin:         &vuln.Metadata.Origin,
					ScannerUri:     &vuln.Metadata.ScannerUri,
					ScannerVersion: &vuln.Metadata.ScannerVersion,
					TimeScanned:    &vuln.Metadata.TimeScanned,
				},
				Vulnerability: gen.VulnerabilityDetails{
					Type: &vuln.Vulnerability.Type,
				},
			}

			for _, namespace := range vuln.Package.Namespaces {
				for _, name := range namespace.Names {
					for _, version := range name.Versions {
						vulnerability.Packages = append(vulnerability.Packages, version.Purl)
					}
				}
			}

			for _, vIDs := range vuln.Vulnerability.VulnerabilityIDs {
				vulnerability.Vulnerability.VulnerabilityIDs = append(vulnerability.Vulnerability.VulnerabilityIDs, vIDs.VulnerabilityID)
			}

			vulnerabilities = append(vulnerabilities, vulnerability)
		}
	}

	return vulnerabilities, nil
}

func searchDependencies(ctx context.Context, gqlClient graphql.Client, pkgSpec model.PkgSpec, searchSoftware bool, startSBOM model.AllHasSBOMTree) (map[string]string, error) {
	dependencies := make(map[string]string)

	pkgs, err := model.Packages(ctx, gqlClient, pkgSpec)
	if err != nil {
		return nil, fmt.Errorf("error searching packages: %w", err)
	}

	for _, pkg := range pkgs.Packages {
		for _, ns := range pkg.Namespaces {
			for _, name := range ns.Names {
				for _, version := range name.Versions {
					dependencies[version.Id] = version.Purl
				}
			}
		}
	}

	doneFirst := false

	queue := []model.PkgSpec{pkgSpec}
	depsFinished := make(map[string]bool)

	for len(queue) > 0 {
		pop := queue[0]
		queue = queue[1:]

		if pop.Id != nil {
			if depsFinished[*pop.Id] {
				continue
			}
			depsFinished[*pop.Id] = true
		}

		hasSboms, err := model.HasSBOMs(ctx, gqlClient, model.HasSBOMSpec{
			Subject: &model.PackageOrArtifactSpec{
				Package: &pop,
			},
		})

		if err != nil {
			return nil, fmt.Errorf("error fetching hasSboms from package spec %+v: %w", pop, err)
		}

		if !doneFirst && searchSoftware {
			hasSboms = &model.HasSBOMsResponse{
				HasSBOM: []model.HasSBOMsHasSBOM{
					{
						AllHasSBOMTree: startSBOM,
					},
				},
			}
		}

		doneFirst = true

		if !searchSoftware {
			for _, hasSbom := range hasSboms.HasSBOM {
				for _, dep := range hasSbom.IncludedDependencies {
					dependencies[dep.Package.Namespaces[0].Names[0].Versions[0].Id] = dep.Package.Namespaces[0].Names[0].Versions[0].Purl
					queue = append(queue, model.PkgSpec{
						Id: &dep.Package.Namespaces[0].Names[0].Versions[0].Id,
					})
				}
			}
		} else {
			for _, hasSbom := range hasSboms.HasSBOM {
				for _, software := range hasSbom.IncludedSoftware {
					switch s := software.(type) {
					case *model.AllHasSBOMTreeIncludedSoftwarePackage:
						dependencies[s.Namespaces[0].Names[0].Versions[0].Id] = s.Namespaces[0].Names[0].Versions[0].Purl
						queue = append(queue, model.PkgSpec{
							Id: &s.Namespaces[0].Names[0].Versions[0].Id,
						})
					case *model.AllHasSBOMTreeIncludedSoftwareArtifact:
						// convert artifact to pkg, then use the pkg id to get the vulnerability
						pkg, err := helpers.GetPkgFromArtifact(gqlClient, s.Id)
						if err != nil {
							return nil, fmt.Errorf("failed to get package attached to artifact %s: %w", s.Id, err)
						}
						dependencies[pkg.Namespaces[0].Names[0].Versions[0].Id] = pkg.Namespaces[0].Names[0].Versions[0].Purl
						queue = append(queue, model.PkgSpec{
							Id: &pkg.Namespaces[0].Names[0].Versions[0].Id,
						})
					}
				}
			}
		}
	}

	return dependencies, nil
}
