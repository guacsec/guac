package guacanalytics

import (
	"context"
	"fmt"
	"strings"

	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"

	"github.com/Khan/genqlient/graphql"
	"github.com/jedib0t/go-pretty/v6/table"
)

const (
	guacType       string = "guac"
	noVulnType     string = "novuln"
	vexLinkStr     string = "vexLink"
	certifyVulnStr string = "certifyVuln"
)

type pkgVersionNeighborQueryResults struct {
	pkgVersionNeighborResponse *model.NeighborsResponse
	isDep                      model.AllHasSBOMTreeIncludedDependenciesIsDependency
}

func getVulnAndVexNeighborsForPackage(ctx context.Context, gqlclient graphql.Client, pkgID string, isDep model.AllHasSBOMTreeIncludedDependenciesIsDependency) (*pkgVersionNeighborQueryResults, error) {
	pkgVersionNeighborResponse, err := model.Neighbors(ctx, gqlclient, pkgID, []model.Edge{model.EdgePackageCertifyVuln, model.EdgePackageCertifyVexStatement})
	if err != nil {
		return nil, fmt.Errorf("failed to get neighbors for pkgID: %s with error %w", pkgID, err)
	}
	return &pkgVersionNeighborQueryResults{pkgVersionNeighborResponse: pkgVersionNeighborResponse, isDep: isDep}, nil
}

func SearchForSBOMViaArtifact(ctx context.Context, gqlclient graphql.Client, searchString string, maxLength int) ([]string, []table.Row, error) {
	var path []string
	var tableRows []table.Row
	checkedPkgIDs := make(map[string]bool)
	var collectedPkgVersionResults []*pkgVersionNeighborQueryResults
	AlreadyIncludedTableRows := make(map[string]bool)

	// Define the node structure for traversal
	type dfsNode struct {
		expanded bool   // Indicates if all node neighbors are added to the queue
		parent   string // Parent node in the traversal
		pkgID    string // Package ID
		depth    int    // Depth in the traversal
	}

	// Initialize the node map and queue with the search string
	nodeMap := map[string]dfsNode{
		searchString: {},
	}
	queue := []string{searchString}

	for len(queue) > 0 {
		now := queue[0]
		queue = queue[1:]
		nowNode := nodeMap[now]

		// Stop traversal if the maximum depth is reached
		if maxLength != 0 && nowNode.depth >= maxLength {
			break
		}

		var foundHasSBOM *model.HasSBOMsResponse

		if nowNode.depth == 0 {
			// Initial depth: treat searchString as an artifact
			artResponse, err := getArtifactResponseFromArtifact(ctx, gqlclient, now)
			if err != nil {
				return nil, nil, fmt.Errorf("getArtifactResponseFromArtifact - error: %v", err)
			}

			artifactID := artResponse.Artifacts[0].Id
			hasSBOMSpec := model.HasSBOMSpec{
				Subject: &model.PackageOrArtifactSpec{
					Artifact: &model.ArtifactSpec{Id: &artifactID},
				},
			}
			foundHasSBOM, err = model.HasSBOMs(ctx, gqlclient, hasSBOMSpec)
			if err != nil {
				return nil, nil, fmt.Errorf("failed getting hasSBOM via artifact: %s with error: %w", now, err)
			}
		} else {
			// Subsequent depths: treat 'now' as a package ID
			hasSBOMSpec := model.HasSBOMSpec{
				Subject: &model.PackageOrArtifactSpec{
					Package: &model.PkgSpec{Id: &now},
				},
			}
			foundHasSBOMPkg, err := model.HasSBOMs(ctx, gqlclient, hasSBOMSpec)
			if err != nil {
				return nil, nil, fmt.Errorf("failed getting hasSBOM via package: %s with error: %w", now, err)
			}
			if foundHasSBOMPkg != nil {
				foundHasSBOM = foundHasSBOMPkg
			} else {
				// If no HasSBOM found via package, try via occurrences
				occurSpec := model.IsOccurrenceSpec{
					Subject: &model.PackageOrSourceSpec{
						Package: &model.PkgSpec{Id: &now},
					},
				}
				occurrences, err := model.Occurrences(ctx, gqlclient, occurSpec)
				if err != nil {
					return nil, nil, fmt.Errorf("error querying for occurrences: %v", err)
				}
				if occurrences != nil && len(occurrences.IsOccurrence) > 0 {
					artifactID := occurrences.IsOccurrence[0].Artifact.Id
					hasSBOMSpec := model.HasSBOMSpec{
						Subject: &model.PackageOrArtifactSpec{
							Artifact: &model.ArtifactSpec{Id: &artifactID},
						},
					}
					foundHasSBOMArt, err := model.HasSBOMs(ctx, gqlclient, hasSBOMSpec)
					if err != nil {
						return nil, nil, fmt.Errorf("failed getting hasSBOM via occurrence: %s with error: %w", now, err)
					}
					if foundHasSBOMArt != nil {
						foundHasSBOM = foundHasSBOMArt
					}
				}
			}
		}

		if foundHasSBOM == nil {
			// If no HasSBOM is found, continue to the next node
			continue
		}

		// Process the HasSBOM results
		for _, hasSBOM := range foundHasSBOM.HasSBOM {
			// Handle included dependencies
			for _, isDep := range hasSBOM.IncludedDependencies {
				if isDep.DependencyPackage.Type == guacType {
					continue
				}
				depPkgID := isDep.DependencyPackage.Namespaces[0].Names[0].Versions[0].Id

				// Check if the dependency package ID is already in the node map
				dfsN, seen := nodeMap[depPkgID]
				if !seen {
					dfsN = dfsNode{
						parent: now,
						pkgID:  depPkgID,
						depth:  nowNode.depth + 1,
					}
					nodeMap[depPkgID] = dfsN
				}

				// **Include the missing `if !dfsN.expanded` check**
				if !dfsN.expanded {
					queue = append(queue, depPkgID)
				}

				// Process vulnerabilities and VEX statements for the dependency
				if !checkedPkgIDs[depPkgID] {
					pkgVersionNeighbors, err := getVulnAndVexNeighborsForPackage(ctx, gqlclient, depPkgID, isDep)
					if err != nil {
						return nil, nil, fmt.Errorf("getVulnAndVexNeighbors failed with error: %w", err)
					}
					collectedPkgVersionResults = append(collectedPkgVersionResults, pkgVersionNeighbors)
					checkedPkgIDs[depPkgID] = true
				}
			}
		}

		nowNode.expanded = true
		nodeMap[now] = nowNode
	}

	// Process collected package version results
	checkedCertifyVulnIDs := make(map[string]bool)

	for _, result := range collectedPkgVersionResults {
		for _, neighbor := range result.pkgVersionNeighborResponse.Neighbors {
			switch n := neighbor.(type) {
			case *model.NeighborsNeighborsCertifyVuln:
				if !checkedCertifyVulnIDs[n.Id] && n.Vulnerability.Type != noVulnType {
					checkedCertifyVulnIDs[n.Id] = true
					for _, vuln := range n.Vulnerability.VulnerabilityIDs {
						if !AlreadyIncludedTableRows[vuln.VulnerabilityID] {
							tableRows = append(tableRows, table.Row{
								certifyVulnStr,
								n.Id,
								"vulnerability ID: " + vuln.VulnerabilityID,
							})
							path = append(path, []string{
								vuln.Id,
								n.Id,
								n.Package.Namespaces[0].Names[0].Versions[0].Id,
								n.Package.Namespaces[0].Names[0].Id,
								n.Package.Namespaces[0].Id,
								n.Package.Id,
							}...)
							AlreadyIncludedTableRows[vuln.VulnerabilityID] = true
						}
					}
					// Include dependency path
					isDep := result.isDep
					path = append(path, []string{
						isDep.Id,
						isDep.Package.Namespaces[0].Names[0].Versions[0].Id,
						isDep.Package.Namespaces[0].Names[0].Id,
						isDep.Package.Namespaces[0].Id,
						isDep.Package.Id,
					}...)
				}
			case *model.NeighborsNeighborsCertifyVEXStatement:
				for _, vuln := range n.Vulnerability.VulnerabilityIDs {
					tableRows = append(tableRows, table.Row{
						vexLinkStr,
						n.Id,
						"vulnerability ID: " + vuln.VulnerabilityID + ", Vex Status: " + string(n.Status) + ", Subject: " + VexSubjectString(n.Subject),
					})
					path = append(path, n.Id, vuln.Id)
				}
				path = append(path, vexSubjectIds(n.Subject)...)
			}
		}
	}

	return path, tableRows, nil
}

// SearchForSBOMViaPkg takes in either a purl or URI for the initial value to find the hasSBOM node.
// From there is recursively searches through all the dependencies to determine if it contains hasSBOM nodes.
// It concurrent checks the package version node if it contains vulnerabilities and VEX data.
// The isPurl parameter is used to know whether the searchString is expected to be a PURL.
func SearchForSBOMViaPkg(ctx context.Context, gqlclient graphql.Client, searchString string, maxLength int, isPurl bool) ([]string, []table.Row, error) {
	var path []string
	var tableRows []table.Row
	checkedPkgIDs := make(map[string]bool)
	var collectedPkgVersionResults []*pkgVersionNeighborQueryResults
	AlreadyIncludedTableRows := make(map[string]bool)

	queue := make([]string, 0) // the queue of nodes in bfs
	type dfsNode struct {
		expanded bool // true once all node neighbors are added to queue
		parent   string
		pkgID    string
		depth    int
	}
	nodeMap := map[string]dfsNode{}

	nodeMap[searchString] = dfsNode{}
	queue = append(queue, searchString)

	for len(queue) > 0 {
		now := queue[0]
		queue = queue[1:]
		nowNode := nodeMap[now]

		if maxLength != 0 && nowNode.depth >= maxLength {
			break
		}

		var foundHasSBOMPkg *model.HasSBOMsResponse
		var err error

		// if the initial depth, check if it's a purl or an SBOM URI. Otherwise, always search by pkgID
		// note that primaryCall will be static throughout the entire function.
		if nowNode.depth == 0 {
			if isPurl {
				pkgResponse, err := getPkgResponseFromPurl(ctx, gqlclient, now)
				if err != nil {
					return nil, nil, fmt.Errorf("getPkgResponseFromPurl - error: %v", err)
				}
				foundHasSBOMPkg, err = model.HasSBOMs(ctx, gqlclient, model.HasSBOMSpec{Subject: &model.PackageOrArtifactSpec{Package: &model.PkgSpec{Id: &pkgResponse.Packages[0].Namespaces[0].Names[0].Versions[0].Id}}})
				if err != nil {
					return nil, nil, fmt.Errorf("failed getting hasSBOM via purl: %s with error :%w", now, err)
				}
			} else {
				foundHasSBOMPkg, err = model.HasSBOMs(ctx, gqlclient, model.HasSBOMSpec{Uri: &now})
				if err != nil {
					return nil, nil, fmt.Errorf("failed getting hasSBOM via URI: %s with error: %w", now, err)
				}
			}
		} else {
			foundHasSBOMPkg, err = model.HasSBOMs(ctx, gqlclient, model.HasSBOMSpec{Subject: &model.PackageOrArtifactSpec{Package: &model.PkgSpec{Id: &now}}})
			if err != nil {
				return nil, nil, fmt.Errorf("failed getting hasSBOM via purl: %s with error :%w", now, err)
			}
		}

		for _, hasSBOM := range foundHasSBOMPkg.HasSBOM {
			if pkgResponse, ok := foundHasSBOMPkg.HasSBOM[0].Subject.(*model.AllHasSBOMTreeSubjectPackage); ok {
				if pkgResponse.Type != guacType {
					if !checkedPkgIDs[pkgResponse.Namespaces[0].Names[0].Versions[0].Id] {
						vulnPath, pkgVulnTableRows, err := queryVulnsViaPackageNeighbors(ctx, gqlclient, pkgResponse.Namespaces[0].Names[0].Versions[0].Id)
						if err != nil {
							return nil, nil, fmt.Errorf("error querying neighbor: %w", err)
						}
						path = append(path, vulnPath...)
						tableRows = append(tableRows, pkgVulnTableRows...)
						path = append([]string{pkgResponse.Namespaces[0].Names[0].Versions[0].Id,
							pkgResponse.Namespaces[0].Names[0].Id, pkgResponse.Namespaces[0].Id,
							pkgResponse.Id}, path...)
						checkedPkgIDs[pkgResponse.Namespaces[0].Names[0].Versions[0].Id] = true
					}
				}
			}
			for _, isDep := range hasSBOM.IncludedDependencies {
				if isDep.DependencyPackage.Type == guacType {
					continue
				}
				depPkgID := isDep.DependencyPackage.Namespaces[0].Names[0].Versions[0].Id
				dfsN, seen := nodeMap[depPkgID]
				if !seen {
					dfsN = dfsNode{
						parent: now,
						pkgID:  depPkgID,
						depth:  nowNode.depth + 1,
					}
					nodeMap[depPkgID] = dfsN
				}
				if !dfsN.expanded {
					queue = append(queue, depPkgID)
				}
				pkgVersionNeighbors, err := getVulnAndVexNeighborsForPackage(ctx, gqlclient, depPkgID, isDep)
				if err != nil {
					return nil, nil, fmt.Errorf("getVulnAndVexNeighbors failed with error: %w", err)
				}
				collectedPkgVersionResults = append(collectedPkgVersionResults, pkgVersionNeighbors)
				checkedPkgIDs[depPkgID] = true

			}

			for _, isDep := range hasSBOM.IncludedDependencies {
				if isDep.DependencyPackage.Type == guacType {
					continue
				}

				depPkgID := isDep.DependencyPackage.Namespaces[0].Names[0].Versions[0].Id
				if _, seen := nodeMap[depPkgID]; !seen {
					dfsN := dfsNode{
						parent: now,
						pkgID:  depPkgID,
						depth:  nowNode.depth + 1,
					}
					nodeMap[depPkgID] = dfsN
				}
			}
		}
		nowNode.expanded = true
		nodeMap[now] = nowNode
	}

	checkedCertifyVulnIDs := make(map[string]bool)

	// Collect results from the channel
	for _, result := range collectedPkgVersionResults {
		for _, neighbor := range result.pkgVersionNeighborResponse.Neighbors {
			if certifyVuln, ok := neighbor.(*model.NeighborsNeighborsCertifyVuln); ok {
				if !checkedCertifyVulnIDs[certifyVuln.Id] && certifyVuln.Vulnerability.Type != noVulnType {
					checkedCertifyVulnIDs[certifyVuln.Id] = true
					if !AlreadyIncludedTableRows[certifyVuln.Vulnerability.VulnerabilityIDs[0].VulnerabilityID] {
						for _, vuln := range certifyVuln.Vulnerability.VulnerabilityIDs {
							tableRows = append(tableRows, table.Row{certifyVulnStr, certifyVuln.Id, "vulnerability ID: " + vuln.VulnerabilityID})
							path = append(path, []string{vuln.Id, certifyVuln.Id,
								certifyVuln.Package.Namespaces[0].Names[0].Versions[0].Id,
								certifyVuln.Package.Namespaces[0].Names[0].Id, certifyVuln.Package.Namespaces[0].Id,
								certifyVuln.Package.Id}...)
						}
						path = append(path, result.isDep.Id, result.isDep.Package.Namespaces[0].Names[0].Versions[0].Id,
							result.isDep.Package.Namespaces[0].Names[0].Id, result.isDep.Package.Namespaces[0].Id,
							result.isDep.Package.Id)

						AlreadyIncludedTableRows[certifyVuln.Vulnerability.VulnerabilityIDs[0].VulnerabilityID] = true
					}
				}
			}

			if certifyVex, ok := neighbor.(*model.NeighborsNeighborsCertifyVEXStatement); ok {
				for _, vuln := range certifyVex.Vulnerability.VulnerabilityIDs {
					tableRows = append(tableRows, table.Row{vexLinkStr, certifyVex.Id, "vulnerability ID: " + vuln.VulnerabilityID + ", Vex Status: " + string(certifyVex.Status) + ", Subject: " + VexSubjectString(certifyVex.Subject)})
					path = append(path, certifyVex.Id, vuln.Id)
				}
				path = append(path, vexSubjectIds(certifyVex.Subject)...)
			}
		}
	}
	return path, tableRows, nil
}

func getArtifactResponseFromArtifact(ctx context.Context, gqlclient graphql.Client, artifactString string) (*model.ArtifactsResponse, error) {

	split := strings.Split(artifactString, ":")
	if len(split) != 2 {
		return nil, fmt.Errorf("failed to split artifact into algo and digest")
	}
	artFilter := &model.ArtifactSpec{
		Algorithm: &split[0],
		Digest:    &split[1],
	}
	artResponse, err := model.Artifacts(ctx, gqlclient, *artFilter)
	if err != nil {
		return nil, fmt.Errorf("error querying for artifact: %v", err)
	}
	if len(artResponse.Artifacts) != 1 {
		return nil, fmt.Errorf("failed to locate artifact based on algorithm and digest")
	}
	return artResponse, nil
}

func getPkgResponseFromPurl(ctx context.Context, gqlclient graphql.Client, purl string) (*model.PackagesResponse, error) {
	pkgInput, err := helpers.PurlToPkg(purl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PURL: %v", err)
	}

	pkgQualifierFilter := []model.PackageQualifierSpec{}
	for _, qualifier := range pkgInput.Qualifiers {
		// to prevent https://github.com/golang/go/discussions/56010
		qualifier := qualifier
		pkgQualifierFilter = append(pkgQualifierFilter, model.PackageQualifierSpec{
			Key:   qualifier.Key,
			Value: &qualifier.Value,
		})
	}

	pkgFilter := &model.PkgSpec{
		Type:       &pkgInput.Type,
		Namespace:  pkgInput.Namespace,
		Name:       &pkgInput.Name,
		Version:    pkgInput.Version,
		Subpath:    pkgInput.Subpath,
		Qualifiers: pkgQualifierFilter,
	}
	pkgResponse, err := model.Packages(ctx, gqlclient, *pkgFilter)
	if err != nil {
		return nil, fmt.Errorf("error querying for package: %v", err)
	}
	if len(pkgResponse.Packages) != 1 {
		return nil, fmt.Errorf("failed to located package based on purl")
	}
	return pkgResponse, nil
}

func vexSubjectIds(s model.AllCertifyVEXStatementSubjectPackageOrArtifact) []string {
	switch v := s.(type) {
	case *model.AllCertifyVEXStatementSubjectArtifact:
		return []string{v.Id}
	case *model.AllCertifyVEXStatementSubjectPackage:
		return []string{
			v.Id,
			v.Namespaces[0].Id,
			v.Namespaces[0].Names[0].Id,
			v.Namespaces[0].Names[0].Versions[0].Id}
	default:
		return []string{}
	}
}

func queryVulnsViaPackageNeighbors(ctx context.Context, gqlclient graphql.Client, pkgVersionID string) ([]string, []table.Row, error) {
	var path []string
	var tableRows []table.Row
	var edgeTypes = []model.Edge{model.EdgePackageCertifyVuln, model.EdgePackageCertifyVexStatement}

	pkgVersionNeighborResponse, err := model.Neighbors(ctx, gqlclient, pkgVersionID, edgeTypes)
	if err != nil {
		return nil, nil, fmt.Errorf("error querying neighbor for vulnerability: %w", err)
	}
	certifyVulnFound := false
	for _, neighbor := range pkgVersionNeighborResponse.Neighbors {
		if certifyVuln, ok := neighbor.(*model.NeighborsNeighborsCertifyVuln); ok {
			certifyVulnFound = true
			if certifyVuln.Vulnerability.Type != noVulnType {
				for _, vuln := range certifyVuln.Vulnerability.VulnerabilityIDs {
					tableRows = append(tableRows, table.Row{certifyVulnStr, certifyVuln.Id, "vulnerability ID: " + vuln.VulnerabilityID})
					path = append(path, []string{vuln.Id, certifyVuln.Id,
						certifyVuln.Package.Namespaces[0].Names[0].Versions[0].Id,
						certifyVuln.Package.Namespaces[0].Names[0].Id, certifyVuln.Package.Namespaces[0].Id,
						certifyVuln.Package.Id}...)
				}
			}
		}

		if certifyVex, ok := neighbor.(*model.NeighborsNeighborsCertifyVEXStatement); ok {
			for _, vuln := range certifyVex.Vulnerability.VulnerabilityIDs {
				tableRows = append(tableRows, table.Row{vexLinkStr, certifyVex.Id, "vulnerability ID: " + vuln.VulnerabilityID + ", Vex Status: " + string(certifyVex.Status) + ", Subject: " + VexSubjectString(certifyVex.Subject)})
				path = append(path, certifyVex.Id, vuln.Id)
			}
			path = append(path, vexSubjectIds(certifyVex.Subject)...)
		}

	}
	if !certifyVulnFound {
		return nil, nil, fmt.Errorf("error certify vulnerability node not found, incomplete data. Please ensure certifier has run by running guacone certifier osv")
	}
	return path, tableRows, nil
}

func VexSubjectString(s model.AllCertifyVEXStatementSubjectPackageOrArtifact) string {
	switch v := s.(type) {
	case *model.AllCertifyVEXStatementSubjectArtifact:
		return fmt.Sprintf("artifact (id:%v) %v:%v", v.Id, v.Algorithm, v.Digest)
	case *model.AllCertifyVEXStatementSubjectPackage:
		return fmt.Sprintf("package (id:%v) %v:%v/%v@%v",
			v.Id,
			v.Type,
			v.Namespaces[0].Namespace,
			v.Namespaces[0].Names[0].Name,
			v.Namespaces[0].Names[0].Versions[0].Version)
	default:
		return "unknown subject"
	}
}
