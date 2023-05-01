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
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/cli"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type queryBadOptions struct {
	// gql endpoint
	graphqlEndpoint string
	depth           int
}

var (
	colVisualizerURL = "Visualizer URL"
	rowBadHeader     = table.Row{colTitleNodeType, colTitleNodeID, colVisualizerURL}
)

var queryBadCmd = &cobra.Command{
	Use:   "query_bad [flags]",
	Short: "query to find more information on certifyBad",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		opts, err := validateQueryBadFlags(
			viper.GetString("gql-endpoint"),
			viper.GetInt("depth"),
		)

		if err != nil {
			fmt.Printf("unable to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		httpClient := http.Client{}
		gqlclient := graphql.NewClient(opts.graphqlEndpoint, &httpClient)

		certifyBadResponse, err := model.CertifyBads(ctx, gqlclient, nil)
		if err != nil {
			logger.Fatalf("error querying for package: %v", err)
		}

		mapCertifyBad := map[string][]model.CertifyBadsCertifyBad{}
		for _, certifyBad := range certifyBadResponse.CertifyBad {
			switch subject := certifyBad.Subject.(type) {
			case *model.AllCertifyBadSubjectPackage:
				purl := helpers.PkgToPurl(subject.Type, subject.Namespaces[0].Namespace, subject.Namespaces[0].Names[0].Name, "", "", []string{})
				purlAndJustification := purl + " (" + certifyBad.Justification + ")"
				mapCertifyBad[purlAndJustification] = append(mapCertifyBad[purlAndJustification], certifyBad)
			case *model.AllCertifyBadSubjectSource:
				namespace := ""
				if !strings.HasPrefix(subject.Namespaces[0].Namespace, "https://") {
					namespace = "https://" + subject.Namespaces[0].Namespace
				} else {
					namespace = subject.Namespaces[0].Namespace
				}
				sourceURL := subject.Type + "+" + namespace + "/" + subject.Namespaces[0].Names[0].Name
				sourceURLAndJustification := sourceURL + " (" + certifyBad.Justification + ")"
				mapCertifyBad[sourceURLAndJustification] = append(mapCertifyBad[sourceURLAndJustification], certifyBad)
			case *model.AllCertifyBadSubjectArtifact:
				artifactDigest := subject.Algorithm + ":" + subject.Digest
				artifactDigestAndJustification := artifactDigest + " (" + certifyBad.Justification + ")"
				mapCertifyBad[artifactDigestAndJustification] = append(mapCertifyBad[artifactDigestAndJustification], certifyBad)
			}
		}

		var certifyBadValues []string
		for certifyBadValue := range mapCertifyBad {
			certifyBadValues = append(certifyBadValues, certifyBadValue)
		}

		prompt := promptui.Select{
			Label: "Select CertifyBad to Query",
			Items: certifyBadValues,
		}

		_, certifyBadSelected, err := prompt.Run()
		if err != nil {
			fmt.Printf("Prompt failed %v\n", err)
			return
		}

		t := table.NewWriter()
		tTemp := table.Table{}
		tTemp.Render()
		t.AppendHeader(rowBadHeader)

		for _, selectedCertifyBad := range mapCertifyBad[certifyBadSelected] {
			var tableRows []table.Row
			switch subject := selectedCertifyBad.Subject.(type) {
			case *model.AllCertifyBadSubjectPackage:
				var path []string
				for _, version := range subject.Namespaces[0].Names[0].Versions {
					pkgPath, err := searchDependencyPackagesReverse(ctx, gqlclient, "", version.Id, opts.depth)
					if err != nil {
						logger.Fatalf("error searching dependency packages match: %v", err)
					}
					if len(pkgPath) > 0 {
						fullCertifyBadPath := append([]string{selectedCertifyBad.Id,
							subject.Namespaces[0].Names[0].Versions[0].Id,
							subject.Namespaces[0].Names[0].Id, subject.Namespaces[0].Id,
							subject.Id}, pkgPath...)
						path = append(path, fullCertifyBadPath...)
					}
				}
				tableRows = append(tableRows, table.Row{badLinkStr, selectedCertifyBad.Id, fmt.Sprintf("Visualizer url: http://localhost:3000/visualize?path=[%v]\n", strings.Join(path, `,`))})
				t.AppendRows(tableRows)
				fmt.Println(t.Render())
			case *model.AllCertifyBadSubjectSource:
				var path []string
				srcFilter := &model.SourceSpec{
					Type:      &subject.Type,
					Namespace: &subject.Namespaces[0].Namespace,
					Name:      &subject.Namespaces[0].Names[0].Name,
					Tag:       subject.Namespaces[0].Names[0].Tag,
					Commit:    subject.Namespaces[0].Names[0].Commit,
				}
				srcResponse, err := model.Sources(ctx, gqlclient, srcFilter)
				if err != nil {
					logger.Fatalf("error querying for sources: %v", err)
				}
				if len(srcResponse.Sources) != 1 {
					logger.Fatalf("failed to located sources based on vcs")
				}

				neighborResponse, err := model.Neighbors(ctx, gqlclient, srcResponse.Sources[0].Namespaces[0].Names[0].Id, []model.Edge{model.EdgeSourceHasSourceAt, model.EdgeSourceIsOccurrence})
				if err != nil {
					logger.Fatalf("error querying neighbors: %v", err)
				}
				for _, neighbor := range neighborResponse.Neighbors {
					switch v := neighbor.(type) {
					case *model.NeighborsNeighborsHasSourceAt:
						path = append(path, v.Id, v.Package.Namespaces[0].Names[0].Versions[0].Id, v.Package.Namespaces[0].Names[0].Id, v.Package.Namespaces[0].Id, v.Package.Id)
					case *model.NeighborsNeighborsIsOccurrence:
						path = append(path, v.Id, v.Artifact.Id)
					default:
						continue
					}
				}

				if len(path) > 0 {
					fullCertifyBadPath := append([]string{selectedCertifyBad.Id,
						subject.Namespaces[0].Names[0].Id,
						subject.Namespaces[0].Id, subject.Id}, path...)
					path = append(path, fullCertifyBadPath...)
				}
				tableRows = append(tableRows, table.Row{badLinkStr, selectedCertifyBad.Id, fmt.Sprintf("Visualizer url: http://localhost:3000/visualize?path=[%v]\n", strings.Join(path, `,`))})
				t.AppendRows(tableRows)
				fmt.Println(t.Render())
			case *model.AllCertifyBadSubjectArtifact:
				var path []string
				artifactFilter := &model.ArtifactSpec{
					Algorithm: &subject.Algorithm,
					Digest:    &subject.Digest,
				}

				artifactResponse, err := model.Artifacts(ctx, gqlclient, artifactFilter)
				if err != nil {
					logger.Fatalf("error querying for artifacts: %v", err)
				}
				if len(artifactResponse.Artifacts) != 1 {
					logger.Fatalf("failed to located artifacts based on (algorithm:digest)")
				}
				neighborResponse, err := model.Neighbors(ctx, gqlclient, artifactResponse.Artifacts[0].Id, []model.Edge{model.EdgeArtifactHashEqual, model.EdgeArtifactIsOccurrence})
				if err != nil {
					logger.Fatalf("error querying neighbors: %v", err)
				}
				for _, neighbor := range neighborResponse.Neighbors {
					switch v := neighbor.(type) {
					case *model.NeighborsNeighborsHashEqual:
						path = append(path, v.Id)
					case *model.NeighborsNeighborsIsOccurrence:
						switch occurrenceSubject := v.Subject.(type) {
						case *model.AllIsOccurrencesTreeSubjectPackage:
							path = append(path, v.Id, occurrenceSubject.Namespaces[0].Names[0].Versions[0].Id, occurrenceSubject.Namespaces[0].Names[0].Id, occurrenceSubject.Namespaces[0].Id, occurrenceSubject.Id)
						case *model.AllIsOccurrencesTreeSubjectSource:
							path = append(path, v.Id, occurrenceSubject.Namespaces[0].Names[0].Id, occurrenceSubject.Namespaces[0].Id, occurrenceSubject.Id)
						}
					default:
						continue
					}
				}
				if len(path) > 0 {
					fullCertifyBadPath := append([]string{selectedCertifyBad.Id,
						subject.Id}, path...)
					path = append(path, fullCertifyBadPath...)
				}
				tableRows = append(tableRows, table.Row{badLinkStr, selectedCertifyBad.Id, fmt.Sprintf("Visualizer url: http://localhost:3000/visualize?path=[%v]\n", strings.Join(path, `,`))})
				t.AppendRows(tableRows)
				fmt.Println(t.Render())
			}
		}
	},
}

func validateQueryBadFlags(graphqlEndpoint string, depth int) (queryBadOptions, error) {
	var opts queryBadOptions
	opts.graphqlEndpoint = graphqlEndpoint
	opts.depth = depth
	return opts, nil
}

func init() {
	set, err := cli.BuildFlags([]string{"depth"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup flag: %v", err)
		os.Exit(1)
	}
	queryBadCmd.Flags().AddFlagSet(set)
	if err := viper.BindPFlags(queryVulnCmd.Flags()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to bind flags: %v", err)
		os.Exit(1)
	}

	rootCmd.AddCommand(queryBadCmd)
}
