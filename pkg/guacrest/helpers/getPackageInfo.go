package helpers

import (
	"context"
	"fmt"
	"github.com/Khan/genqlient/graphql"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	gen "github.com/guacsec/guac/pkg/guacrest/generated"
	"github.com/guacsec/guac/pkg/logging"
)

type QueryType struct {
	Vulns        *bool
	Dependencies *bool
	Licenses     *bool
}

func GetInfoForPackage(ctx context.Context, gqlClient graphql.Client, pkgInput *model.PkgInputSpec, shouldQuery QueryType) (*gen.PackageInfoResponseJSONResponse, error) {
	logger := logging.FromContext(ctx)
	response := gen.PackageInfoResponseJSONResponse{}

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

	var purls []string

	for _, pkg := range pkgs.Packages {
		for _, namespace := range pkg.Namespaces {
			for _, n := range namespace.Names {
				for _, v := range n.Versions {
					purls = append(purls, v.Purl)
				}
			}
		}
	}

	response.Packages = purls

	if shouldQuery.Vulns != nil && *shouldQuery.Vulns {
		logger.Infof("Searching for vulnerabilities in package %s", pkgInput.Name)
		vulnerabilities, err := searchAttachedVulns(ctx, gqlClient, pkgSpec)
		if err != nil {
			return nil, err
		}
		response.Vulnerabilities = &vulnerabilities
	}
	if shouldQuery.Dependencies != nil && *shouldQuery.Dependencies {
		logger.Infof("Searching for dependencies in package %s", pkgInput.Name)

		var dependencies []gen.PackageInfo

		deps, err := searchDependencies(ctx, gqlClient, pkgSpec)
		if err != nil {
			return nil, err
		}
		for _, purl := range deps {
			dependencies = append(dependencies, purl)
		}
		response.Dependencies = &dependencies
	}

	return &response, nil
}

// searchAttachedVulns searches for vulnerabilities associated with the given package
// and its dependencies via a BFS.
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
func searchAttachedVulns(ctx context.Context, gqlClient graphql.Client, pkgSpec model.PkgSpec) ([]gen.Vulnerability, error) {
	logger := logging.FromContext(ctx)
	var vulnerabilities []gen.Vulnerability

	pkgs, err := searchDependencies(ctx, gqlClient, pkgSpec)
	if err != nil {
		return nil, fmt.Errorf("error searching dependencies: %w", err)
	}

	for pkg, purl := range pkgs {
		logger.Infof("package: %+v, purl: %s", pkg, purl)
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

func searchDependencies(ctx context.Context, gqlClient graphql.Client, pkgSpec model.PkgSpec) (map[string]string, error) {
	dependencies := make(map[string]string)

	pkgs, err := model.Packages(ctx, gqlClient, pkgSpec)
	if err != nil {
		return nil, fmt.Errorf("error searching packages: %w", err)
	}

	for _, pkg := range pkgs.Packages {
		dependencies[pkg.Namespaces[0].Names[0].Versions[0].Id] = pkg.Namespaces[0].Names[0].Versions[0].Purl
	}

	queue := []model.PkgSpec{pkgSpec}

	for len(queue) > 0 {
		pop := queue[0]
		queue = queue[1:]

		hasSboms, err := model.HasSBOMs(ctx, gqlClient, model.HasSBOMSpec{
			Subject: &model.PackageOrArtifactSpec{
				Package: &pop,
			},
		})

		//isDeps, err := model.Dependencies(ctx, gqlClient, model.IsDependencySpec{
		//	DependencyPackage: &pop,
		//})
		if err != nil {
			return nil, fmt.Errorf("error fetching hasSboms from package spec %+v: %w", pop, err)
		}

		for _, hasSbom := range hasSboms.HasSBOM {
			for _, dep := range hasSbom.IncludedDependencies {
				dependencies[dep.Package.Namespaces[0].Names[0].Versions[0].Id] = dep.Package.Namespaces[0].Names[0].Versions[0].Purl
				queue = append(queue, model.PkgSpec{
					Id: &dep.Package.Namespaces[0].Names[0].Versions[0].Id,
				})
			}
		}
	}

	return dependencies, nil
}
