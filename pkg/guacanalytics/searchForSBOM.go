package guacanalytics

import (
	"context"
	"fmt"
	"github.com/Khan/genqlient/graphql"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/jedib0t/go-pretty/v6/table"
	"strings"
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

type artifactVersionNeighborQueryResults struct {
	pkgVersionNeighborResponse *model.NeighborsResponse
	isArt                      model.AllHasSBOMTreeIncludedOccurrencesIsOccurrence
}

func getVulnAndVexNeighborsForPackage(ctx context.Context, gqlclient graphql.Client, pkgID string, isDep model.AllHasSBOMTreeIncludedDependenciesIsDependency) (*pkgVersionNeighborQueryResults, error) {
	pkgVersionNeighborResponse, err := model.Neighbors(ctx, gqlclient, pkgID, []model.Edge{model.EdgePackageCertifyVuln, model.EdgePackageCertifyVexStatement})
	if err != nil {
		return nil, fmt.Errorf("failed to get neighbors for pkgID: %s with error %w", pkgID, err)
	}
	return &pkgVersionNeighborQueryResults{pkgVersionNeighborResponse: pkgVersionNeighborResponse, isDep: isDep}, nil
}

func getVulnAndVexNeighborsForArtifact(ctx context.Context, gqlclient graphql.Client, pkgID string, isArt model.AllHasSBOMTreeIncludedOccurrencesIsOccurrence) (*artifactVersionNeighborQueryResults, error) {
	pkgVersionNeighborResponse, err := model.Neighbors(ctx, gqlclient, pkgID, []model.Edge{model.EdgeArtifactCertifyVexStatement})
	if err != nil {
		return nil, fmt.Errorf("failed to get neighbors for pkgID: %s with error %w", pkgID, err)
	}
	return &artifactVersionNeighborQueryResults{pkgVersionNeighborResponse: pkgVersionNeighborResponse, isArt: isArt}, nil
}

// SearchForSBOMViaPkg takes in either a purl or URI for the initial value to find the hasSBOM node.
// From there is recursively searches through all the dependencies to determine if it contains hasSBOM nodes.
// It concurrent checks the package version node if it contains vulnerabilities and VEX data.
// The primaryCall parameter is used to know whether the searchString is expected to be a PURL.
func SearchForSBOMViaPkg(ctx context.Context, gqlclient graphql.Client, searchString string, maxLength int, primaryCall bool) ([]string, []table.Row, error) {
	var path []string
	var tableRows []table.Row
	checkedPkgIDs := make(map[string]bool)
	var collectedPkgVersionResults []*pkgVersionNeighborQueryResults

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
		if nowNode.depth == 0 && primaryCall {
			pkgResponse, err := getPkgResponseFromPurl(ctx, gqlclient, now)
			if err != nil {
				return nil, nil, fmt.Errorf("getPkgResponseFromPurl - error: %w", err)
			}
			foundHasSBOMPkg, err = model.HasSBOMs(ctx, gqlclient, model.HasSBOMSpec{Subject: &model.PackageOrArtifactSpec{Package: &model.PkgSpec{Id: &pkgResponse.Packages[0].Namespaces[0].Names[0].Versions[0].Id}}})
			if err != nil {
				return nil, nil, fmt.Errorf("failed getting hasSBOM via purl: %s with error :%w", now, err)
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

// SearchForSBOMViaArtifact takes in either a URI for the initial value to find the hasSBOM node.
// It concurrently checks the artifact node if it contains vulnerabilities and VEX data.
// The primaryCall parameter is used to know whether the searchString is expected to be an artifact or a package.
func SearchForSBOMViaArtifact(ctx context.Context, gqlclient graphql.Client, searchString string, maxLength int, primaryCall bool) ([]string, []table.Row, error) {
	var path []string
	var tableRows []table.Row
	checkedArtifactIDs := make(map[string]bool)
	var collectedArtifactResults []*artifactVersionNeighborQueryResults

	queue := make([]string, 0) // the queue of nodes in bfs
	type dfsNode struct {
		expanded bool // true once all node neighbors are added to queue
		parent   string
		artID    string
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

		if nowNode.depth == 0 && primaryCall {
			split := strings.Split(now, ":")
			if len(split) != 2 {
				return nil, nil, fmt.Errorf("error splitting search string %s, search string should have two sections algorithm and digest: %v", now, split)
			}
			algorithm := strings.ToLower(split[0])
			digest := strings.ToLower(split[1])

			foundHasSBOMPkg, err = model.HasSBOMs(ctx, gqlclient, model.HasSBOMSpec{Subject: &model.PackageOrArtifactSpec{
				Artifact: &model.ArtifactSpec{
					Algorithm: &algorithm,
					Digest:    &digest,
				},
			}})
			if err != nil {
				return nil, nil, fmt.Errorf("failed getting hasSBOM via URI: %s with error: %w", now, err)
			}
		} else {
			foundHasSBOMPkg, err = model.HasSBOMs(ctx, gqlclient, model.HasSBOMSpec{Subject: &model.PackageOrArtifactSpec{Artifact: &model.ArtifactSpec{Id: &now}}})
			if err != nil {
				return nil, nil, fmt.Errorf("failed getting hasSBOM via artifact: %s with error :%w", now, err)
			}
		}

		for _, hasSBOM := range foundHasSBOMPkg.HasSBOM {
			if pkgResponse, ok := foundHasSBOMPkg.HasSBOM[0].Subject.(*model.AllHasSBOMTreeSubjectPackage); ok {
				if pkgResponse.Type != guacType {
					if !checkedArtifactIDs[pkgResponse.Namespaces[0].Names[0].Versions[0].Id] {
						vulnPath, pkgVulnTableRows, err := queryVulnsViaPackageNeighbors(ctx, gqlclient, pkgResponse.Namespaces[0].Names[0].Versions[0].Id)
						if err != nil {
							return nil, nil, fmt.Errorf("error querying neighbor: %w", err)
						}
						path = append(path, vulnPath...)
						tableRows = append(tableRows, pkgVulnTableRows...)
						path = append([]string{pkgResponse.Namespaces[0].Names[0].Versions[0].Id,
							pkgResponse.Namespaces[0].Names[0].Id, pkgResponse.Namespaces[0].Id,
							pkgResponse.Id}, path...)
						checkedArtifactIDs[pkgResponse.Namespaces[0].Names[0].Versions[0].Id] = true
					}
				}
			}
			for _, isOcc := range hasSBOM.IncludedOccurrences {
				if *isOcc.Subject.GetTypename() == guacType {
					continue
				}
				var matchingArtifactIDs []string
				matchingArtifactIDs = append(matchingArtifactIDs, isOcc.Artifact.Id)

				for _, artID := range matchingArtifactIDs {
					dfsN, seen := nodeMap[artID]
					if !seen {
						dfsN = dfsNode{
							parent: now,
							artID:  artID,
							depth:  nowNode.depth + 1,
						}
						nodeMap[artID] = dfsN
					}
					if !dfsN.expanded {
						queue = append(queue, artID)
					}
					artifactNeighbors, err := getVulnAndVexNeighborsForArtifact(ctx, gqlclient, artID, isOcc)
					if err != nil {
						return nil, nil, fmt.Errorf("getVulnAndVexNeighborsForArtifact failed with error: %w", err)
					}
					collectedArtifactResults = append(collectedArtifactResults, artifactNeighbors)
					checkedArtifactIDs[artID] = true
				}
			}
		}
		nowNode.expanded = true
		nodeMap[now] = nowNode
	}

	checkedCertifyVulnIDs := make(map[string]bool)

	// Collect results from the channel
	for _, result := range collectedArtifactResults {
		for _, neighbor := range result.pkgVersionNeighborResponse.Neighbors {
			if certifyVuln, ok := neighbor.(*model.NeighborsNeighborsCertifyVuln); ok {
				if !checkedCertifyVulnIDs[certifyVuln.Id] && certifyVuln.Vulnerability.Type != noVulnType {
					checkedCertifyVulnIDs[certifyVuln.Id] = true
					for _, vuln := range certifyVuln.Vulnerability.VulnerabilityIDs {
						tableRows = append(tableRows, table.Row{certifyVulnStr, certifyVuln.Id, "vulnerability ID: " + vuln.VulnerabilityID})
						path = append(path, []string{vuln.Id, certifyVuln.Id,
							certifyVuln.Package.Namespaces[0].Names[0].Versions[0].Id,
							certifyVuln.Package.Namespaces[0].Names[0].Id, certifyVuln.Package.Namespaces[0].Id,
							certifyVuln.Package.Id}...)
					}
					path = append(path, result.isArt.Id, result.isArt.Artifact.Id)
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
