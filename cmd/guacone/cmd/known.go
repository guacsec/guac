//
// Copyright 2023 The GUAC Authors.
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

package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/Khan/genqlient/graphql"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	hashEqualStr        string = "hashEqual"
	scorecardStr        string = "scorecard"
	occurrenceStr       string = "occurrence"
	hasSrcAtStr         string = "hasSrcAt"
	hasSBOMStr          string = "hasSBOM"
	hasSLSAStr          string = "hasSLSA"
	certifyVulnStr      string = "certifyVuln"
	vexLinkStr          string = "vexLink"
	badLinkStr          string = "badLink"
	goodLinkStr         string = "goodLink"
	pkgEqualStr         string = "pkgEqual"
	packageSubjectType  string = "package"
	sourceSubjectType   string = "source"
	artifactSubjectType string = "artifact"
)

type queryKnownOptions struct {
	// gql endpoint
	graphqlEndpoint string
	// package, source or artifact
	subjectType string
	// purl / source (<vcs_tool>+<transport>) / artifact (algorithm:digest)
	subject string
	// search depth to search (0 is unlimited, 1 is just root node neighbors)
	searchDepth int
}

type neighbors struct {
	hashEquals   []*model.NeighborsNeighborsHashEqual
	scorecards   []*model.NeighborsNeighborsCertifyScorecard
	occurrences  []*model.NeighborsNeighborsIsOccurrence
	hasSrcAt     []*model.NeighborsNeighborsHasSourceAt
	hasSBOMs     []*model.NeighborsNeighborsHasSBOM
	hasSLSAs     []*model.NeighborsNeighborsHasSLSA
	certifyVulns []*model.NeighborsNeighborsCertifyVuln
	vexLinks     []*model.NeighborsNeighborsCertifyVEXStatement
	badLinks     []*model.NeighborsNeighborsCertifyBad
	goodLinks    []*model.NeighborsNeighborsCertifyGood
	pkgEquals    []*model.NeighborsNeighborsPkgEqual
}

var (
	colSubject       = "Subject"
	colTitleNodeType = "Node Type"
	colTitleNodeID   = "Node ID #"
	colTitleNodeInfo = "Additional Information"
	rowHeader        = table.Row{colSubject, colTitleNodeType, colTitleNodeID, colTitleNodeInfo}
)

var queryKnownCmd = &cobra.Command{
	Use:   "known [flags] <type> <subject>",
	Short: "Query for all the available information on a package, source, or artifact.",
	Long: `Query for all the available information on a package, source, or artifact.
  <type> must be either "package", "source", or "artifact".
  <subject> is in the form of "<purl>" for package, "<vcs_tool>+<transport>" for source, or "<algorithm>:<digest>" for artiact.`,
	Run: func(cmd *cobra.Command, args []string) {
		ctx := logging.WithLogger(context.Background())

		opts, err := validateQueryKnownFlags(
			viper.GetString("gql-addr"),
			viper.GetInt("search-depth"),
			args,
		)

		if err != nil {
			fmt.Printf("unable to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		httpClient := http.Client{}
		gqlclient := graphql.NewClient(opts.graphqlEndpoint, &httpClient)

		t := table.NewWriter()
		tTemp := table.Table{}
		tTemp.Render()
		t.AppendHeader(rowHeader)

		var path []string
		queue := []target{{
			depth:       0,
			subjectType: opts.subjectType,
			subject:     opts.subject,
		}}

		visited := map[string]bool{}
		for len(queue) > 0 {
			targetNode := queue[0]
			queue = queue[1:]

			if opts.searchDepth > 0 && targetNode.depth >= opts.searchDepth {
				break
			}
			if ok := visited[targetNode.subject]; ok {
				continue
			}

			retVisited, retFrontier := exploreKnown(ctx, gqlclient, t, path, targetNode)
			queue = append(queue, retFrontier...)
			visited[targetNode.subject] = true
			for _, v := range retVisited {
				visited[v] = true
			}
		}
	},
}

type target struct {
	depth       int
	subjectType string
	subject     string
}

func exploreKnown(ctx context.Context, gqlclient graphql.Client, t table.Writer, path []string, node target) (retVisited []string, retFrontier []target) {

	logger := logging.FromContext(ctx)
	switch node.subjectType {
	case packageSubjectType:
		pkgInput, err := helpers.PurlToPkg(node.subject)
		if err != nil {
			logger.Fatalf("failed to parse PURL: %v", err)
		}

		var pkgQualifierFilter []model.PackageQualifierSpec
		for _, qualifier := range pkgInput.Qualifiers {
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
			logger.Fatalf("error querying for package: %v", err)
		}
		if len(pkgResponse.Packages) != 1 {
			if pkgInput.Version == nil || *pkgInput.Version == "" {
				// do not explore generic packages without versions
				logger.Infof("skipping exploration of generic pacakages without versions: %v", node.subject)
				return
			}
			logger.Fatalf("failed to located package based on purl: %v", node.subject)
		}

		retVisited = append(retVisited, helpers.AllPkgTreeToPurl(&pkgResponse.Packages[0].AllPkgTree))

		pkgNameNeighbors, neighborsPath, err := queryKnownNeighbors(ctx, gqlclient, pkgResponse.Packages[0].Namespaces[0].Names[0].Id)
		if err != nil {
			logger.Fatalf("error querying for package name neighbors: %v", err)
		}
		t.SetTitle("Package Name Nodes")
		t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, pkgNameNeighbors, hasSrcAtStr, packageSubjectType, node.subject))
		t.AppendSeparator()
		t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, pkgNameNeighbors, badLinkStr, packageSubjectType, node.subject))
		t.AppendSeparator()
		t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, pkgNameNeighbors, goodLinkStr, packageSubjectType, node.subject))
		t.AppendSeparator()

		path = append([]string{pkgResponse.Packages[0].Namespaces[0].Names[0].Id,
			pkgResponse.Packages[0].Namespaces[0].Id,
			pkgResponse.Packages[0].Id}, neighborsPath...)

		fmt.Println(t.Render())
		fmt.Printf("Visualizer url: http://localhost:3000/?path=%v\n", strings.Join(removeDuplicateValuesFromPath(path), `,`))

		retFrontier = append(retFrontier, getFrontierBasedOnNode(ctx, gqlclient, pkgNameNeighbors, packageSubjectType, node)...)

		pkgVersionNeighbors, neighborsPath, err := queryKnownNeighbors(ctx, gqlclient, pkgResponse.Packages[0].Namespaces[0].Names[0].Versions[0].Id)
		if err != nil {
			logger.Fatalf("error querying for package version neighbors: %v", err)
		}

		// instantiate new table for package version nodes
		t := table.NewWriter()
		tTemp := table.Table{}
		tTemp.Render()
		t.AppendHeader(rowHeader)

		t.SetTitle("Package Version Nodes")
		t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, pkgVersionNeighbors, hasSrcAtStr, packageSubjectType, node.subject))
		t.AppendSeparator()
		t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, pkgVersionNeighbors, occurrenceStr, packageSubjectType, node.subject))
		t.AppendSeparator()
		t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, pkgVersionNeighbors, certifyVulnStr, packageSubjectType, node.subject))
		t.AppendSeparator()
		t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, pkgVersionNeighbors, hasSBOMStr, packageSubjectType, node.subject))
		t.AppendSeparator()
		t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, pkgVersionNeighbors, hasSLSAStr, packageSubjectType, node.subject))
		t.AppendSeparator()
		t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, pkgVersionNeighbors, vexLinkStr, packageSubjectType, node.subject))
		t.AppendSeparator()
		t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, pkgVersionNeighbors, pkgEqualStr, packageSubjectType, node.subject))
		t.AppendSeparator()
		t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, pkgVersionNeighbors, badLinkStr, packageSubjectType, node.subject))
		t.AppendSeparator()
		t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, pkgVersionNeighbors, goodLinkStr, packageSubjectType, node.subject))
		path = append([]string{pkgResponse.Packages[0].Namespaces[0].Names[0].Versions[0].Id,
			pkgResponse.Packages[0].Namespaces[0].Names[0].Id, pkgResponse.Packages[0].Namespaces[0].Id,
			pkgResponse.Packages[0].Id}, neighborsPath...)

		// Get frontier for pacakge version nodes
		retFrontier = append(retFrontier, getFrontierBasedOnNode(ctx, gqlclient, pkgVersionNeighbors, packageSubjectType, node)...)

		fmt.Println(t.Render())
		fmt.Printf("Visualizer url: http://localhost:3000/?path=%v\n", strings.Join(removeDuplicateValuesFromPath(path), `,`))

	case sourceSubjectType:
		srcInput, err := helpers.VcsToSrc(node.subject)
		if err != nil {
			logger.Fatalf("failed to parse source %v: %v", node.subject, err)
		}

		srcFilter := &model.SourceSpec{
			Type:      &srcInput.Type,
			Namespace: &srcInput.Namespace,
			Name:      &srcInput.Name,
			Tag:       srcInput.Tag,
			Commit:    srcInput.Commit,
		}
		srcResponse, err := model.Sources(ctx, gqlclient, *srcFilter)
		if err != nil {
			logger.Fatalf("error querying for sources: %v", err)
		}
		if len(srcResponse.Sources) != 1 {
			logger.Fatalf("failed to located sources based on vcs")
		}
		sourceNeighbors, neighborsPath, err := queryKnownNeighbors(ctx, gqlclient, srcResponse.Sources[0].Namespaces[0].Names[0].Id)
		if err != nil {
			logger.Fatalf("error querying for source neighbors: %v", err)
		}
		t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, sourceNeighbors, hasSrcAtStr, sourceSubjectType, node.subject))
		t.AppendSeparator()
		t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, sourceNeighbors, occurrenceStr, sourceSubjectType, node.subject))
		t.AppendSeparator()
		t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, sourceNeighbors, scorecardStr, sourceSubjectType, node.subject))
		t.AppendSeparator()
		t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, sourceNeighbors, badLinkStr, sourceSubjectType, node.subject))
		t.AppendSeparator()
		t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, sourceNeighbors, goodLinkStr, sourceSubjectType, node.subject))
		path = append([]string{srcResponse.Sources[0].Namespaces[0].Names[0].Id,
			srcResponse.Sources[0].Namespaces[0].Id, srcResponse.Sources[0].Id}, neighborsPath...)

		fmt.Println(t.Render())
		fmt.Printf("Visualizer url: http://localhost:3000/?path=%v\n", strings.Join(removeDuplicateValuesFromPath(path), `,`))

		retFrontier = append(retFrontier, getFrontierBasedOnNode(ctx, gqlclient, sourceNeighbors, sourceSubjectType, node)...)
	case artifactSubjectType:
		split := strings.Split(node.subject, ":")
		if len(split) != 2 {
			logger.Fatalf("failed to parse artifact. Needs to be in algorithm:digest form")
		}
		artifactFilter := &model.ArtifactSpec{
			Algorithm: ptrfrom.String(strings.ToLower(string(split[0]))),
			Digest:    ptrfrom.String(strings.ToLower(string(split[1]))),
		}

		artifactResponse, err := model.Artifacts(ctx, gqlclient, *artifactFilter)
		if err != nil {
			logger.Fatalf("error querying for artifacts: %v", err)
		}
		if len(artifactResponse.Artifacts) != 1 {
			logger.Fatalf("failed to located artifacts based on (algorithm:digest)")
		}
		artifactNeighbors, neighborsPath, err := queryKnownNeighbors(ctx, gqlclient, artifactResponse.Artifacts[0].Id)
		if err != nil {
			logger.Fatalf("error querying for artifact neighbors: %v", err)
		}
		t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, artifactNeighbors, hashEqualStr, artifactSubjectType, node.subject))
		t.AppendSeparator()
		t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, artifactNeighbors, occurrenceStr, artifactSubjectType, node.subject))
		t.AppendSeparator()
		t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, artifactNeighbors, hasSBOMStr, artifactSubjectType, node.subject))
		t.AppendSeparator()
		t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, artifactNeighbors, hasSLSAStr, artifactSubjectType, node.subject))
		t.AppendSeparator()
		t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, artifactNeighbors, vexLinkStr, artifactSubjectType, node.subject))
		t.AppendSeparator()
		t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, artifactNeighbors, badLinkStr, artifactSubjectType, node.subject))
		t.AppendSeparator()
		t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, artifactNeighbors, goodLinkStr, artifactSubjectType, node.subject))
		path = append([]string{artifactResponse.Artifacts[0].Id}, neighborsPath...)

		fmt.Println(t.Render())
		fmt.Printf("Visualizer url: http://localhost:3000/?path=%v\n", strings.Join(removeDuplicateValuesFromPath(path), `,`))

		retFrontier = append(retFrontier, getFrontierBasedOnNode(ctx, gqlclient, artifactNeighbors, artifactSubjectType, node)...)
	default:
		logger.Fatalf("expected type to be either a package, source or artifact")
	}
	return
}

func queryKnownNeighbors(ctx context.Context, gqlclient graphql.Client, subjectQueryID string) (*neighbors, []string, error) {
	collectedNeighbors := &neighbors{}
	var path []string
	neighborResponse, err := model.Neighbors(ctx, gqlclient, subjectQueryID, []model.Edge{})
	if err != nil {
		return nil, nil, fmt.Errorf("error querying neighbors: %v", err)
	}
	for _, neighbor := range neighborResponse.Neighbors {
		switch v := neighbor.(type) {
		case *model.NeighborsNeighborsCertifyVuln:
			collectedNeighbors.certifyVulns = append(collectedNeighbors.certifyVulns, v)
			path = append(path, v.Id)
		case *model.NeighborsNeighborsCertifyBad:
			collectedNeighbors.badLinks = append(collectedNeighbors.badLinks, v)
			path = append(path, v.Id)
		case *model.NeighborsNeighborsCertifyGood:
			collectedNeighbors.goodLinks = append(collectedNeighbors.goodLinks, v)
			path = append(path, v.Id)
		case *model.NeighborsNeighborsCertifyScorecard:
			collectedNeighbors.scorecards = append(collectedNeighbors.scorecards, v)
			path = append(path, v.Id)
		case *model.NeighborsNeighborsCertifyVEXStatement:
			collectedNeighbors.vexLinks = append(collectedNeighbors.vexLinks, v)
			path = append(path, v.Id)
		case *model.NeighborsNeighborsHasSBOM:
			collectedNeighbors.hasSBOMs = append(collectedNeighbors.hasSBOMs, v)
			path = append(path, v.Id)
		case *model.NeighborsNeighborsHasSLSA:
			collectedNeighbors.hasSLSAs = append(collectedNeighbors.hasSLSAs, v)
			path = append(path, v.Id)
		case *model.NeighborsNeighborsHasSourceAt:
			collectedNeighbors.hasSrcAt = append(collectedNeighbors.hasSrcAt, v)
			path = append(path, v.Id)
		case *model.NeighborsNeighborsHashEqual:
			collectedNeighbors.hashEquals = append(collectedNeighbors.hashEquals, v)
			path = append(path, v.Id)
		case *model.NeighborsNeighborsIsOccurrence:
			collectedNeighbors.occurrences = append(collectedNeighbors.occurrences, v)
			path = append(path, v.Id)
		case *model.NeighborsNeighborsPkgEqual:
			collectedNeighbors.pkgEquals = append(collectedNeighbors.pkgEquals, v)
			path = append(path, v.Id)
		default:
			continue
		}
	}
	return collectedNeighbors, path, nil
}

func getOutputBasedOnNode(ctx context.Context, gqlclient graphql.Client, collectedNeighbors *neighbors, nodeType string, subjectType string, subject string) []table.Row {
	logger := logging.FromContext(ctx)
	var tableRows []table.Row
	switch nodeType {
	case certifyVulnStr:
		for _, certVuln := range collectedNeighbors.certifyVulns {
			if certVuln.Vulnerability.Type != noVulnType {
				for _, vuln := range certVuln.Vulnerability.VulnerabilityIDs {
					tableRows = append(tableRows, table.Row{subject, certifyVulnStr, certVuln.Id, "vulnerability ID: " + vuln.VulnerabilityID})
				}
			} else {
				tableRows = append(tableRows, table.Row{subject, certifyVulnStr, certVuln.Id, "vulnerability ID: " + noVulnType})
			}
		}
	case badLinkStr:
		for _, bad := range collectedNeighbors.badLinks {
			tableRows = append(tableRows, table.Row{subject, badLinkStr, bad.Id, "justification: " + bad.Justification})
		}
	case goodLinkStr:
		for _, good := range collectedNeighbors.goodLinks {
			tableRows = append(tableRows, table.Row{subject, goodLinkStr, good.Id, "justification: " + good.Justification})
		}
	case scorecardStr:
		for _, score := range collectedNeighbors.scorecards {
			tableRows = append(tableRows, table.Row{subject, scorecardStr, score.Id, "Overall Score: " + fmt.Sprintf("%f", score.Scorecard.AggregateScore)})
		}
	case vexLinkStr:
		for _, vex := range collectedNeighbors.vexLinks {
			tableRows = append(tableRows, table.Row{subject, vexLinkStr, vex.Id, "Vex Status: " + vex.Status})
		}
	case hasSBOMStr:
		for _, sbom := range collectedNeighbors.hasSBOMs {
			tableRows = append(tableRows, table.Row{subject, hasSBOMStr, sbom.Id, "SBOM Download Location: " + sbom.DownloadLocation})
		}
	case hasSLSAStr:
		if len(collectedNeighbors.hasSLSAs) > 0 {
			for _, slsa := range collectedNeighbors.hasSLSAs {
				tableRows = append(tableRows, table.Row{subject, hasSLSAStr, slsa.Id, "SLSA Attestation Location: " + slsa.Slsa.Origin})
			}
		} else {
			// if there is an isOccurrence, check to see if there are slsa attestation associated with it
			for _, occurrence := range collectedNeighbors.occurrences {
				artifactFilter := &model.ArtifactSpec{
					Algorithm: &occurrence.Artifact.Algorithm,
					Digest:    &occurrence.Artifact.Digest,
				}
				artifactResponse, err := model.Artifacts(ctx, gqlclient, *artifactFilter)
				if err != nil {
					logger.Debugf("error querying for artifacts: %v", err)
				}
				if len(artifactResponse.Artifacts) != 1 {
					logger.Debugf("failed to located artifacts based on (algorithm:digest)")
				}
				neighborResponseHasSLSA, err := model.Neighbors(ctx, gqlclient, artifactResponse.Artifacts[0].Id, []model.Edge{model.EdgeArtifactHasSlsa})
				if err != nil {
					logger.Debugf("error querying neighbors: %v", err)
				} else {
					for _, neighborHasSLSA := range neighborResponseHasSLSA.Neighbors {
						if hasSLSA, ok := neighborHasSLSA.(*model.NeighborsNeighborsHasSLSA); ok {
							tableRows = append(tableRows, table.Row{subject, hasSLSAStr, hasSLSA.Id, "SLSA Attestation Location: " + hasSLSA.Slsa.Origin})
						}
					}
				}
			}
		}
	case hasSrcAtStr:
		for _, src := range collectedNeighbors.hasSrcAt {
			if subjectType == packageSubjectType {
				namespace := ""
				if !strings.HasPrefix(src.Source.Namespaces[0].Namespace, "https://") {
					namespace = "https://" + src.Source.Namespaces[0].Namespace
				} else {
					namespace = src.Source.Namespaces[0].Namespace
				}
				tableRows = append(tableRows, table.Row{subject, hasSrcAtStr, src.Id, "Source: " + src.Source.Type + "+" + namespace + "/" +
					src.Source.Namespaces[0].Names[0].Name})
			} else {
				purl := helpers.PkgToPurl(src.Package.Type, src.Package.Namespaces[0].Namespace,
					src.Package.Namespaces[0].Names[0].Name, "", "", []string{})

				tableRows = append(tableRows, table.Row{subject, hasSrcAtStr, src.Id, "Source for Package: " + purl})
			}
		}
	case hashEqualStr:
		for _, hash := range collectedNeighbors.hashEquals {
			tableRows = append(tableRows, table.Row{subject, hashEqualStr, hash.Id, ""})
		}
	case occurrenceStr:
		for _, occurrence := range collectedNeighbors.occurrences {
			if subjectType == artifactSubjectType {
				switch v := occurrence.Subject.(type) {
				case *model.AllIsOccurrencesTreeSubjectPackage:
					purl := helpers.PkgToPurl(v.Type, v.Namespaces[0].Namespace,
						v.Namespaces[0].Names[0].Name, v.Namespaces[0].Names[0].Versions[0].Version, "", []string{})

					tableRows = append(tableRows, table.Row{subject, occurrenceStr, occurrence.Id, "Occurrence for Package: " + purl})
				case *model.AllIsOccurrencesTreeSubjectSource:
					namespace := ""
					if !strings.HasPrefix(v.Namespaces[0].Namespace, "https://") {
						namespace = "https://" + v.Namespaces[0].Namespace
					} else {
						namespace = v.Namespaces[0].Namespace
					}
					tableRows = append(tableRows, table.Row{subject, occurrenceStr, occurrence.Id, "Occurrence for Package: " + v.Type + "+" + namespace + "/" +
						v.Namespaces[0].Names[0].Name})
				}
			} else {
				tableRows = append(tableRows, table.Row{subject, occurrenceStr, occurrence.Id, "Occurrence for Artifact: " + occurrence.Artifact.Algorithm + ":" + occurrence.Artifact.Digest})
			}
		}
	case pkgEqualStr:
		for _, equal := range collectedNeighbors.pkgEquals {
			tableRows = append(tableRows, table.Row{subject, pkgEqualStr, equal.Id, ""})
		}
	}

	return tableRows
}

func allArtifactTreeToSubject(v *model.AllArtifactTree) string {
	return fmt.Sprintf("%s:%s", v.Algorithm, v.Digest)
}

func allSourceTreeToSubject(v *model.AllSourceTree) string {
	// <vcs_tool>+<transport>://<host_name>[/<path_to_repository>][@<revision_tag_or_branch>][#<sub_path>]

	namespace := ""
	if !strings.HasPrefix(v.Namespaces[0].Namespace, "https://") {
		namespace = "https://" + v.Namespaces[0].Namespace
	} else {
		namespace = v.Namespaces[0].Namespace
	}

	s := fmt.Sprintf("%s+%s", v.Type, namespace)
	if len(v.Namespaces[0].Names) > 0 {
		name := v.Namespaces[0].Names[0]
		s += "/" + name.Name
		if name.Commit != nil {
			s += "@" + *name.Commit
		} else if name.Tag != nil {
			s += "@" + *name.Tag
		}
	}

	return s
}

func getFrontierBasedOnNode(ctx context.Context, gqlclient graphql.Client, collectedNeighbors *neighbors, subjectType string, currentTarget target) []target {
	var frontier []target

	// case certifyVulnStr:
	// case badLinkStr:
	// case goodLinkStr:
	// case scorecardStr:
	// case vexLinkStr:

	//case hasSBOMStr:
	for _, sbom := range collectedNeighbors.hasSBOMs {
		for _, s := range sbom.IncludedSoftware {
			switch s := s.(type) {
			case *model.AllHasSBOMTreeIncludedSoftwarePackage:
				frontier = append(frontier, target{
					subjectType: packageSubjectType,
					subject:     helpers.AllPkgTreeToPurl(&s.AllPkgTree),
				})
			case *model.AllHasSBOMTreeIncludedSoftwareArtifact:
				frontier = append(frontier, target{
					subjectType: artifactSubjectType,
					subject:     allArtifactTreeToSubject(&s.AllArtifactTree),
				})
			}
		}
	}

	// case hasSLSAStr:
	if len(collectedNeighbors.hasSLSAs) > 0 {
		for _, slsa := range collectedNeighbors.hasSLSAs {
			for _, v := range slsa.Slsa.BuiltFrom {
				frontier = append(frontier, target{
					subjectType: artifactSubjectType,
					subject:     allArtifactTreeToSubject(&v.AllArtifactTree),
				})
			}
		}
	}
	//case hasSrcAtStr:
	for _, src := range collectedNeighbors.hasSrcAt {
		if subjectType == packageSubjectType {
			frontier = append(frontier, target{
				subjectType: sourceSubjectType,
				subject:     allSourceTreeToSubject(&src.Source.AllSourceTree),
			})

		} else {
			frontier = append(frontier, target{
				subjectType: packageSubjectType,
				subject:     helpers.AllPkgTreeToPurl(&src.Package.AllPkgTree),
			})

		}
	}
	//case hashEqualStr:
	for _, hash := range collectedNeighbors.hashEquals {
		for _, v := range hash.Artifacts {
			frontier = append(frontier, target{
				subjectType: artifactSubjectType,
				subject:     allArtifactTreeToSubject(&v.AllArtifactTree),
			})
		}
	}
	//case occurrenceStr:
	for _, occurrence := range collectedNeighbors.occurrences {
		if subjectType == artifactSubjectType {
			switch v := occurrence.Subject.(type) {
			case *model.AllIsOccurrencesTreeSubjectPackage:
				frontier = append(frontier, target{
					subjectType: packageSubjectType,
					subject:     helpers.AllPkgTreeToPurl(&v.AllPkgTree),
				})

			case *model.AllIsOccurrencesTreeSubjectSource:
				frontier = append(frontier, target{
					subjectType: sourceSubjectType,
					subject:     allSourceTreeToSubject(&v.AllSourceTree),
				})

			}
		} else {
			frontier = append(frontier, target{
				subjectType: artifactSubjectType,
				subject:     allArtifactTreeToSubject(&occurrence.Artifact.AllArtifactTree),
			})
		}
	}
	//case pkgEqualStr:
	for _, equal := range collectedNeighbors.pkgEquals {
		for _, v := range equal.Packages {
			frontier = append(frontier, target{
				subjectType: artifactSubjectType,
				subject:     helpers.AllPkgTreeToPurl(&v.AllPkgTree),
			})
		}

	}

	for i := 0; i < len(frontier); i++ {
		frontier[i].depth = currentTarget.depth + 1
	}
	return frontier
}

func validateQueryKnownFlags(graphqlEndpoint string, searchDepth int, args []string) (queryKnownOptions, error) {
	var opts queryKnownOptions
	opts.graphqlEndpoint = graphqlEndpoint

	if searchDepth < 0 {
		return opts, fmt.Errorf("known depth must be non-negative")
	}

	opts.searchDepth = searchDepth

	if len(args) != 2 {
		return opts, fmt.Errorf("expected positional arguments for <type> <subject>")
	}
	opts.subjectType = args[0]
	if opts.subjectType != "package" && opts.subjectType != "source" && opts.subjectType != "artifact" {
		return opts, fmt.Errorf("expected type to be either a package, source or artifact")
	}
	opts.subject = args[1]

	return opts, nil
}

func init() {
	queryCmd.AddCommand(queryKnownCmd)
}
