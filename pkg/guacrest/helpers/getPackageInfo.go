package helpers

import (
	"context"
	"fmt"

	model "github.com/guacsec/guac/pkg/assembler/clients/generated"

	"github.com/Khan/genqlient/graphql"
	gen "github.com/guacsec/guac/pkg/guacrest/generated"
	"github.com/guacsec/guac/pkg/logging"
)

type QueryType struct {
	Vulns        bool
	Dependencies bool
	LatestSBOM   bool
}

type dfsNode struct {
	expanded bool
	depth    int
}

func ConvertPkgInputSpecToPkgSpec(pkgInput *model.PkgInputSpec) model.PkgSpec {
	pkgSpec := model.PkgSpec{
		Type: &pkgInput.Type,
		Name: &pkgInput.Name,
	}

	if pkgInput.Namespace != nil && *pkgInput.Namespace != "" {
		pkgSpec.Namespace = pkgInput.Namespace
	}
	if pkgInput.Version != nil && *pkgInput.Version != "" {
		pkgSpec.Version = pkgInput.Version
	}
	if pkgInput.Subpath != nil && *pkgInput.Subpath != "" {
		pkgSpec.Subpath = pkgInput.Subpath
	}

	return pkgSpec
}

func GetPurlsForPkg(ctx context.Context, gqlClient graphql.Client, pkgSpec model.PkgSpec) ([]string, []string, error) {
	var purls []string
	var packageIds []string

	pkgs, err := model.Packages(ctx, gqlClient, pkgSpec)
	if err != nil {
		return nil, nil, err
	}

	for _, pkg := range pkgs.Packages {
		for _, namespace := range pkg.Namespaces {
			for _, n := range namespace.Names {
				for _, v := range n.Versions {
					purls = append(purls, v.Purl)
					packageIds = append(packageIds, v.Id)
				}
			}
		}
	}

	return purls, packageIds, nil
}

//func GetInfoForPkg(ctx context.Context, gqlClient graphql.Client, pkgInput *model.PkgInputSpec, shouldQuery QueryType) {
//	logger := logging.FromContext(ctx)
//	response := gen.PackageInfoResponseJSONResponse{}
//
//	pkgSpec := model.PkgSpec{
//		Type: &pkgInput.Type,
//		Name: &pkgInput.Name,
//	}
//
//	if pkgInput.Namespace != nil && *pkgInput.Namespace != "" {
//		pkgSpec.Namespace = pkgInput.Namespace
//	}
//	if pkgInput.Version != nil && *pkgInput.Version != "" {
//		pkgSpec.Version = pkgInput.Version
//	}
//	if pkgInput.Subpath != nil && *pkgInput.Subpath != "" {
//		pkgSpec.Subpath = pkgInput.Subpath
//	}
//
//	pkgs, err := model.Packages(ctx, gqlClient, pkgSpec)
//	if err != nil {
//		return nil, err
//	}
//
//	var purls []string
//	var packageIds []string
//
//	for _, pkg := range pkgs.Packages {
//		for _, namespace := range pkg.Namespaces {
//			for _, n := range namespace.Names {
//				for _, v := range n.Versions {
//					purls = append(purls, v.Purl)
//					packageIds = append(packageIds, v.Id)
//				}
//			}
//		}
//	}
//
//	//response.Packages = purls
//
//	searchSoftware := false
//
//	latestSbom := &model.AllHasSBOMTree{}
//
//	// If the LatestSBOM query is specified then all other queries should be for the latest SBOM
//	if shouldQuery.LatestSBOM {
//		latestSbom, err = LatestSBOMFromID(ctx, gqlClient, packageIds)
//		if err != nil {
//			return nil, err
//		}
//		searchSoftware = true
//	}
//
//	if shouldQuery.Vulns {
//		logger.Infof("Searching for vulnerabilities in package %s", pkgInput.Name)
//		vulnerabilities, err := searchAttachedVulns(ctx, gqlClient, pkgSpec, searchSoftware, *latestSbom)
//		if err != nil {
//			return nil, err
//		}
//		response.Vulnerabilities = &vulnerabilities
//	}
//	//if shouldQuery.Dependencies {
//	//	logger.Infof("Searching for dependencies in package %s", pkgInput.Name)
//	//
//	//	var dependencies []gen.PackageInfo
//	//
//	//	deps, err := SearchDependencies(ctx, gqlClient, pkgSpec, searchSoftware, *latestSbom)
//	//	if err != nil {
//	//		return nil, err
//	//	}
//	//	for _, purl := range deps {
//	//		dependencies = append(dependencies, purl)
//	//	}
//	//	response.Dependencies = &dependencies
//	//}
//
//	return &response, nil
//}

// SearchPkgForVulns searches for vulnerabilities associated with the given package
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
func SearchPkgForVulns(ctx context.Context, gqlClient graphql.Client, pkgSpec model.PkgSpec, searchSoftware bool, startSBOM model.AllHasSBOMTree) ([]gen.Vulnerability, error) {
	//logger := logging.FromContext(ctx)
	var vulnerabilities []gen.Vulnerability

	pkgs, err := SearchDependencies(ctx, gqlClient, pkgSpec, searchSoftware, startSBOM)
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

func SearchDependencies(ctx context.Context, gqlClient graphql.Client, pkgSpec model.PkgSpec, searchSoftware bool, startSBOM model.AllHasSBOMTree) (map[string]string, error) {
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
						pkg, err := getPkgFromArtifact(gqlClient, s.Id)
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

// SearchVulnerabilitiesByArtifact searches for vulnerabilities associated with the given artifact.
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
func SearchVulnerabilitiesByArtifact(ctx context.Context, gqlClient graphql.Client, artifactSpec model.ArtifactSpec, searchSoftware bool) ([]gen.Vulnerability, error) {
	logger := logging.FromContext(ctx)
	var vulnerabilities []gen.Vulnerability

	nodeMap, queue, processedVulns, err := searchDependenciesByArtifact(ctx, gqlClient, artifactSpec, searchSoftware)
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
			logger.Errorf("Error fetching vulnerabilities for package %s: %v", pkgID, err)
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
func searchDependenciesByArtifact(ctx context.Context, gqlClient graphql.Client, artifactSpec model.ArtifactSpec, searchSoftware bool) (map[string]dfsNode, []string, map[string]bool, error) {
	hasSBOMs, err := model.HasSBOMs(ctx, gqlClient, model.HasSBOMSpec{
		Subject: &model.PackageOrArtifactSpec{
			Artifact: &artifactSpec,
		},
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error fetching hasSBOMs for artifact: %w", err)
	}

	nodeMap := make(map[string]dfsNode)
	queue := []string{}

	// Map to track processed vulnerabilities
	processedVulns := make(map[string]bool)

	if !searchSoftware {
		for _, hasSBOM := range hasSBOMs.HasSBOM {
			for _, includedDep := range hasSBOM.IncludedDependencies {
				pkg := includedDep.DependencyPackage
				pkgID := pkg.Namespaces[0].Names[0].Versions[0].Id
				nodeMap[pkgID] = dfsNode{depth: 1}
				queue = append(queue, pkgID)
			}
		}
	} else {
		for _, hasSbom := range hasSBOMs.HasSBOM {
			for _, software := range hasSbom.IncludedSoftware {
				switch s := software.(type) {
				case *model.AllHasSBOMTreeIncludedSoftwarePackage:
					pkgID := s.Namespaces[0].Names[0].Versions[0].Id
					nodeMap[pkgID] = dfsNode{depth: 1}
					queue = append(queue, pkgID)
				case *model.AllHasSBOMTreeIncludedSoftwareArtifact:
					// convert artifact to pkg, then use the pkg id to get the vulnerability
					pkg, err := getPkgFromArtifact(gqlClient, s.Id)
					if err != nil {
						return nil, nil, nil, fmt.Errorf("failed to get package attached to artifact %s: %w", s.Id, err)
					}
					pkgID := pkg.Namespaces[0].Names[0].Versions[0].Id
					nodeMap[pkgID] = dfsNode{depth: 1}
					queue = append(queue, pkgID)
				}
			}
		}
	}
	return nodeMap, queue, processedVulns, nil
}
