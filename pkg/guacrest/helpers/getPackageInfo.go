package helpers

import (
	"context"
	"fmt"
	"github.com/Khan/genqlient/graphql"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	gen "github.com/guacsec/guac/pkg/guacrest/generated"
	"github.com/guacsec/guac/pkg/logging"
)

func GetInfoForPackage(ctx context.Context, gqlClient graphql.Client, pkgInput *model.PkgInputSpec, shouldSearchVulns *bool) (*gen.PackageInfoResponseJSONResponse, error) {
	logger := logging.FromContext(ctx)
	var purls []string
	var vulnerabilities []gen.Vulnerability

	pkgSpec := model.PkgSpec{
		Type: &pkgInput.Type,
		Name: &pkgInput.Name,
	}

	if *pkgInput.Namespace != "" {
		pkgSpec.Namespace = pkgInput.Namespace
	}
	if *pkgInput.Version != "" {
		pkgSpec.Version = pkgInput.Version
	}
	if *pkgInput.Subpath != "" {
		pkgSpec.Subpath = pkgInput.Subpath
	}

	pkgs, err := model.Packages(ctx, gqlClient, pkgSpec)
	if err != nil {
		return nil, err
	}

	for _, pkg := range pkgs.Packages {
		for _, namespace := range pkg.Namespaces {
			for _, n := range namespace.Names {
				for _, v := range n.Versions {
					purls = append(purls, v.Purl)
				}
			}
		}
	}

	if shouldSearchVulns != nil && *shouldSearchVulns {
		logger.Infof("Searching for vulnerabilities in package %s", pkgInput.Name)
		vulns, err := model.CertifyVuln(ctx, gqlClient, model.CertifyVulnSpec{
			Package: &pkgSpec,
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

	response := gen.PackageInfoResponseJSONResponse{
		Packages:        &purls,
		Vulnerabilities: &vulnerabilities,
	}

	return &response, nil
}
