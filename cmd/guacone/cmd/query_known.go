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
	"github.com/guacsec/guac/pkg/cli"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	hashEqualStr   string = "hashEqual"
	scorecardStr   string = "scorecard"
	occurrenceStr  string = "occurrence"
	hasSrcAtStr    string = "hasSrcAt"
	hasSBOMStr     string = "hasSBOM"
	hasSLSAStr     string = "hasSLSA"
	certifyVulnStr string = "certifyVuln"
	vexLinkStr     string = "vexLink"
	badLinkStr     string = "badLink"
	goodLinkStr    string = "goodLink"
	pkgEqualStr    string = "pkgEqual"
)

type queryKnownOptions struct {
	// gql endpoint
	graphqlEndpoint string
	// package, source or artifact
	subjectType string
	// purl / source (<vcs_tool>+<transport>) / artifact (algorithm:digest)
	subject string
	// if type is package, true if at pkgName (for all versions) or false for a specific version
	pkgName bool
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
	colTitleNodeType = "Node Type"
	colTitleNodeID   = "Node ID #"
	colTitleNodeInfo = "Additional Information"
	rowHeader        = table.Row{colTitleNodeType, colTitleNodeID, colTitleNodeInfo}
)

var queryKnownCmd = &cobra.Command{
	Use:   "query_known [flags] purl / source (<vcs_tool>+<transport>) / artifact (algorithm:digest)",
	Short: "query for all the available information on a package, source or artifact",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		opts, err := validateQueryKnownFlags(
			viper.GetString("gql-endpoint"),
			viper.GetString("type"),
			viper.GetBool("pkgName"),
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
		// you can also instantiate the object directly
		tTemp := table.Table{}
		tTemp.Render()
		t.AppendHeader(rowHeader)
		path := []string{}
		switch opts.subjectType {
		case "package":
			pkgInput, err := helpers.PurlToPkg(opts.subject)
			if err != nil {
				logger.Fatalf("failed to parse PURL: %v", err)
			}

			pkgQualifierFilter := []model.PackageQualifierSpec{}
			for _, qualifier := range pkgInput.Qualifiers {
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
			pkgResponse, err := model.Packages(ctx, gqlclient, pkgFilter)
			if err != nil {
				logger.Fatalf("error querying for package: %v", err)
			}
			if len(pkgResponse.Packages) != 1 {
				logger.Fatalf("failed to located package based on purl")
			}

			if opts.pkgName {
				pkgNameNeighbors, neighborsPath, err := queryKnownNeighbors(ctx, gqlclient, pkgResponse.Packages[0].Namespaces[0].Names[0].Id)
				if err != nil {
					logger.Fatalf("error querying for package name neighbors: %v", err)
				}
				t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, pkgNameNeighbors, hasSrcAtStr))
				t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, pkgNameNeighbors, badLinkStr))
				t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, pkgNameNeighbors, goodLinkStr))
				path = append([]string{pkgResponse.Packages[0].Namespaces[0].Names[0].Id,
					pkgResponse.Packages[0].Namespaces[0].Id,
					pkgResponse.Packages[0].Id}, neighborsPath...)
			} else {
				pkgVersionNeighbors, neighborsPath, err := queryKnownNeighbors(ctx, gqlclient, pkgResponse.Packages[0].Namespaces[0].Names[0].Versions[0].Id)
				if err != nil {
					logger.Fatalf("error querying for package version neighbors: %v", err)
				}
				t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, pkgVersionNeighbors, hasSrcAtStr))
				t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, pkgVersionNeighbors, occurrenceStr))
				t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, pkgVersionNeighbors, certifyVulnStr))
				t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, pkgVersionNeighbors, hasSBOMStr))
				t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, pkgVersionNeighbors, hasSLSAStr))
				t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, pkgVersionNeighbors, vexLinkStr))
				t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, pkgVersionNeighbors, pkgEqualStr))
				t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, pkgVersionNeighbors, badLinkStr))
				t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, pkgVersionNeighbors, goodLinkStr))
				path = append([]string{pkgResponse.Packages[0].Namespaces[0].Names[0].Versions[0].Id,
					pkgResponse.Packages[0].Namespaces[0].Names[0].Id, pkgResponse.Packages[0].Namespaces[0].Id,
					pkgResponse.Packages[0].Id}, neighborsPath...)
			}
		case "source":
			srcInput, err := helpers.VcsToSrc(opts.subject)
			if err != nil {
				logger.Fatalf("failed to parse source: %v", err)
			}

			srcFilter := &model.SourceSpec{
				Type:      &srcInput.Type,
				Namespace: &srcInput.Namespace,
				Name:      &srcInput.Name,
				Tag:       srcInput.Tag,
				Commit:    srcInput.Commit,
			}
			srcResponse, err := model.Sources(ctx, gqlclient, srcFilter)
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

			t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, sourceNeighbors, hasSrcAtStr))
			t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, sourceNeighbors, occurrenceStr))
			t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, sourceNeighbors, scorecardStr))
			t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, sourceNeighbors, badLinkStr))
			t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, sourceNeighbors, goodLinkStr))
			path = append([]string{srcResponse.Sources[0].Namespaces[0].Names[0].Id,
				srcResponse.Sources[0].Namespaces[0].Id, srcResponse.Sources[0].Id}, neighborsPath...)
		case "artifact":
			split := strings.Split(opts.subject, ":")
			if len(split) != 2 {
				logger.Fatalf("failed to parse artifact. Needs to be in algorithm:digest form")
			}
			artifactFilter := &model.ArtifactSpec{
				Algorithm: ptrfrom.String(strings.ToLower(string(split[0]))),
				Digest:    ptrfrom.String(strings.ToLower(string(split[1]))),
			}

			artifactResponse, err := model.Artifacts(ctx, gqlclient, artifactFilter)
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

			t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, artifactNeighbors, hashEqualStr))
			t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, artifactNeighbors, occurrenceStr))
			t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, artifactNeighbors, hasSBOMStr))
			t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, artifactNeighbors, hasSLSAStr))
			t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, artifactNeighbors, vexLinkStr))
			t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, artifactNeighbors, badLinkStr))
			t.AppendRows(getOutputBasedOnNode(ctx, gqlclient, artifactNeighbors, goodLinkStr))
			path = append([]string{artifactResponse.Artifacts[0].Id}, neighborsPath...)
		default:
			logger.Fatalf("expected type to be either a package, source or artifact")
		}
		fmt.Println(t.Render())
		fmt.Printf("Visualizer url: http://localhost:3000/visualize?path=[%v]\n", strings.Join(path, `,`))
	},
}

func queryKnownNeighbors(ctx context.Context, gqlclient graphql.Client, subjectQueryID string) (*neighbors, []string, error) {
	collectedNeighbors := &neighbors{}
	path := []string{}
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

func getOutputBasedOnNode(ctx context.Context, gqlclient graphql.Client, collectedNeighbors *neighbors, nodeType string) []table.Row {
	logger := logging.FromContext(ctx)
	tableRows := []table.Row{}
	switch nodeType {
	case certifyVulnStr:
		for _, vuln := range collectedNeighbors.certifyVulns {
			if osv, ok := vuln.Vulnerability.(*model.AllCertifyVulnVulnerabilityOSV); ok {
				tableRows = append(tableRows, table.Row{certifyVulnStr, vuln.Id, "vulnerability ID: " + osv.OsvId})
			} else if cve, ok := vuln.Vulnerability.(*model.AllCertifyVulnVulnerabilityCVE); ok {
				tableRows = append(tableRows, table.Row{certifyVulnStr, vuln.Id, "vulnerability ID: " + cve.CveId})
			} else if ghsa, ok := vuln.Vulnerability.(*model.AllCertifyVulnVulnerabilityGHSA); ok {
				tableRows = append(tableRows, table.Row{certifyVulnStr, vuln.Id, "vulnerability ID: " + ghsa.GhsaId})
			} else if noVuln, ok := vuln.Vulnerability.(*model.AllCertifyVulnVulnerabilityNoVuln); ok {
				tableRows = append(tableRows, table.Row{certifyVulnStr, vuln.Id, "vulnerability ID: " + *noVuln.Typename})
			}
		}
	case badLinkStr:
		for _, bad := range collectedNeighbors.badLinks {
			tableRows = append(tableRows, table.Row{badLinkStr, bad.Id, "justification: " + bad.Justification})
		}
	case goodLinkStr:
		for _, good := range collectedNeighbors.goodLinks {
			tableRows = append(tableRows, table.Row{goodLinkStr, good.Id, "justification: " + good.Justification})
		}
	case scorecardStr:
		for _, score := range collectedNeighbors.scorecards {
			tableRows = append(tableRows, table.Row{scorecardStr, score.Id, "Overall Score: " + fmt.Sprintf("%f", score.Scorecard.AggregateScore)})
		}
	case vexLinkStr:
		for _, vex := range collectedNeighbors.vexLinks {
			tableRows = append(tableRows, table.Row{vexLinkStr, vex.Id, "Vex Status: " + vex.Status})
		}
	case hasSBOMStr:
		for _, sbom := range collectedNeighbors.hasSBOMs {
			tableRows = append(tableRows, table.Row{hasSBOMStr, sbom.Id, "SBOM Download Location: " + sbom.DownloadLocation})
		}
	case hasSLSAStr:
		for _, slsa := range collectedNeighbors.hasSLSAs {
			tableRows = append(tableRows, table.Row{hasSLSAStr, slsa.Id, "SLSA Attestation Location: " + slsa.Slsa.Origin})
		}
		// if there is an isOccurrence, check to see if there are slsa attestation associated with it
		for _, occurrence := range collectedNeighbors.occurrences {
			artifactFilter := &model.ArtifactSpec{
				Algorithm: &occurrence.Artifact.Algorithm,
				Digest:    &occurrence.Artifact.Digest,
			}
			artifactResponse, err := model.Artifacts(ctx, gqlclient, artifactFilter)
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
						tableRows = append(tableRows, table.Row{hasSLSAStr, hasSLSA.Id, "SLSA Attestation Location: " + hasSLSA.Slsa.Origin})
					}
				}
			}
		}
	case hasSrcAtStr:
		for _, src := range collectedNeighbors.hasSrcAt {
			namespace := ""
			if !strings.HasPrefix(src.Source.Namespaces[0].Namespace, "https://") {
				namespace = "https://" + src.Source.Namespaces[0].Namespace
			} else {
				namespace = src.Source.Namespaces[0].Namespace
			}
			tableRows = append(tableRows, table.Row{hasSrcAtStr, src.Id, "Source: " + src.Source.Type + "+" + namespace + "/" + src.Source.Namespaces[0].Names[0].Name})
		}
	case hashEqualStr:
		for _, hash := range collectedNeighbors.hashEquals {
			tableRows = append(tableRows, table.Row{hashEqualStr, hash.Id, ""})
		}
	case occurrenceStr:
		for _, occurrence := range collectedNeighbors.occurrences {
			tableRows = append(tableRows, table.Row{occurrenceStr, occurrence.Id, ""})
		}
	case pkgEqualStr:
		for _, equal := range collectedNeighbors.pkgEquals {
			tableRows = append(tableRows, table.Row{pkgEqualStr, equal.Id, ""})
		}
	}

	return tableRows
}

func validateQueryKnownFlags(graphqlEndpoint, queryType string, pkgName bool, args []string) (queryKnownOptions, error) {
	var opts queryKnownOptions
	opts.graphqlEndpoint = graphqlEndpoint
	opts.pkgName = pkgName
	if queryType != "package" && queryType != "source" && queryType != "artifact" {
		return opts, fmt.Errorf("expected type to be either a package, source or artifact")
	}
	opts.subjectType = queryType

	if len(args) > 0 {
		opts.subject = args[0]
	} else {
		return opts, fmt.Errorf("expected subject input to be purl / source (<vcs_tool>+<transport>) / artifact (algorithm:digest)")
	}

	return opts, nil
}

func init() {
	set, err := cli.BuildFlags([]string{"type", "pkgName"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup flag: %v", err)
		os.Exit(1)
	}
	queryKnownCmd.Flags().AddFlagSet(set)
	if err := viper.BindPFlags(queryKnownCmd.Flags()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to bind flags: %v", err)
		os.Exit(1)
	}

	rootCmd.AddCommand(queryKnownCmd)
}
