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
	"github.com/guacsec/guac/pkg/logging"
	"net/url"
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
func searchVulnerabilitiesViaPkg(ctx context.Context, gqlClient graphql.Client, purl string, includeDependencies *bool) ([]gen.Vulnerability, error) {
	logger := logging.FromContext(ctx)
	var vulnerabilities []gen.Vulnerability

	unescapedPurl, err := url.QueryUnescape(purl)
	if err != nil {
		return nil, fmt.Errorf("failed to unescape package url: %w", err)
	}
	pkg, err := helpers.FindPackageWithPurl(ctx, gqlClient, unescapedPurl)
	if err != nil {
		return nil, fmt.Errorf("failed to find package with purl: %w", err)
	}

	var n = &pkg

	pkgs, err := mapPkgNodesToPurls(ctx, gqlClient, []node{n})
	if err != nil {
		return nil, fmt.Errorf("failed to map package nodes to purls: %w", err)
	}

	if includeDependencies != nil && *includeDependencies {
		dependencies, err := GetDepsForPackage(ctx, gqlClient, purl)
		if err != nil {
			return nil, fmt.Errorf("error searching dependencies: %w", err)
		}
		for k, v := range dependencies {
			pkgs[k] = v
		}
	}

	for pkg := range pkgs {
		vulns, err := model.CertifyVuln(ctx, gqlClient, model.CertifyVulnSpec{
			Package: &model.PkgSpec{
				Id: &pkg,
			},
		})
		if err != nil {
			logger.Errorf("error fetching vulnerabilities from package spec: %v", err)
			return nil, helpers.Err502
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

			vulnerability.Package = vuln.Package.Namespaces[0].Names[0].Versions[0].Purl

			for _, vIDs := range vuln.Vulnerability.VulnerabilityIDs {
				vulnerability.Vulnerability.VulnerabilityIDs = append(vulnerability.Vulnerability.VulnerabilityIDs, vIDs.VulnerabilityID)
			}

			vulnerabilities = append(vulnerabilities, vulnerability)
		}
	}

	return vulnerabilities, nil
}
