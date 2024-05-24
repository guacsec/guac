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

package cmd

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/Khan/genqlient/graphql"
	"github.com/dominikbraun/graph"
	analyzer "github.com/guacsec/guac/pkg/analyzer"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type AnalyzeOpts struct {
	Metadata   bool
	InclSoft   bool
	InclDeps   bool
	InclOccur  bool
	Namespaces bool
	URI        bool
	PURL       bool
	ID         bool
}

var analyzeCmd = &cobra.Command{
	Use:   "analyze <operation> <sboms> [flags] ",
	Short: "analyze is a CLI tool tailored for comparing, intersecting, and merging Software Bill of Materials (SBOMs) within GUAC",
	Long: `Diff Analysis: Compare two SBOMs to identify differences in their software components, versions, and dependencies.
  Intersection Analysis: Determine the intersection of two SBOMs, highlighting common software components shared between them.
  Union Analysis: Combine two SBOMs to create a unified SBOM, merging software component lists while maintaining version integrity.`,
	Example: `
  Ingest the SBOMs to analyze:
  $ guacone collect files guac-data-main/docs/spdx/syft-spdx-k8s.gcr.io-kube-apiserver.v1.24.4.json
  $ guacone collect files guac-data-main/docs/spdx/spdx_vuln.json 

  Difference
  $ guacone analyze diff --uri --sboms=https://anchore.com/syft/image/ghcr.io/guacsec/vul-image-latest-6fd9de7b-9bec-4ae7-99d9-4b5e5ef6b869,https://anchore.com/syft/image/k8s.gcr.io/kube-apiserver-v1.24.4-b15339bc-a146-476e-a789-6a65e4e22e54
  
  Union
  $ guacone analyze union --uri --sboms=https://anchore.com/syft/image/ghcr.io/guacsec/vul-image-latest-6fd9de7b-9bec-4ae7-99d9-4b5e5ef6b869,https://anchore.com/syft/image/k8s.gcr.io/kube-apiserver-v1.24.4-b15339bc-a146-476e-a789-6a65e4e22e54
  
  Intersection
  $ guacone analyze intersect --uri --sboms=https://anchore.com/syft/image/ghcr.io/guacsec/vul-image-latest-6fd9de7b-9bec-4ae7-99d9-4b5e5ef6b869,https://anchore.com/syft/image/k8s.gcr.io/kube-apiserver-v1.24.4-b15339bc-a146-476e-a789-6a65e4e22e54
  `,
	Run: func(cmd *cobra.Command, args []string) {

		if len(args) < 1 || len(args) > 1 {
			fmt.Println("Required 1 positional arguments, got", len(args))
			os.Exit(1)
		}

		if args[0] != "intersect" && args[0] != "union" && args[0] != "diff" {
			fmt.Println("Invalid positional argument. Must be one of: intersect, union or diff.")
			os.Exit(1)
		}

		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)
		httpClient := http.Client{}
		gqlclient := graphql.NewClient(viper.GetString("gql-addr"), &httpClient)

		slsas, errSlsa := cmd.Flags().GetStringSlice("slsa")
		sboms, errSbom := cmd.Flags().GetStringSlice("sboms")
		uri, _ := cmd.Flags().GetBool("uri")
		purl, _ := cmd.Flags().GetBool("purl")

		metadata, _ := cmd.Flags().GetBool("metadata")
		inclSoft, _ := cmd.Flags().GetBool("incl-soft")
		inclDeps, _ := cmd.Flags().GetBool("incl-deps")
		inclOccur, _ := cmd.Flags().GetBool("incl-occur")
		namespaces, _ := cmd.Flags().GetBool("namespaces")
		id, _ := cmd.Flags().GetBool("id")
		test, _ := cmd.Flags().GetString("test")

		var graphs []graph.Graph[string, *analyzer.Node]
		var err error

		if test == "" {
			if err = verifyAnalyzeFlags(slsas, sboms, errSlsa, errSbom, uri, purl, id); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %s", err)
				_ = cmd.Help()
				os.Exit(1)
			}

			//create graphs
			graphs, err = hasSBOMToGraph(ctx, gqlclient, sboms, AnalyzeOpts{
				Metadata: metadata, InclSoft: inclSoft, InclDeps: inclDeps, InclOccur: inclOccur, Namespaces: namespaces, URI: uri, PURL: purl, ID: id})

			if err != nil {
				logger.Fatalf("Unable to generate graphs: %v", err)
			}

		} else {
			graphs, err = readTwoSBOM(test)
			if err != nil {
				logger.Fatalf("Unable to generate graphs: %v", err)
			}
		}

		if args[0] == "diff" {
			analysisOne, analysisTwo, err := analyzer.HighlightAnalysis(graphs[0], graphs[1], 0)
			if err != nil {
				logger.Fatalf("unable to generate diff analysis: %v", err)
			}

			diffs, err := analyzer.CompareAllPaths(analysisOne, analysisTwo)
			if err != nil {
				logger.Fatalf("unable to generate diff analysis: %v", err)
			}

			if err = printDiffedPathTable(diffs); err != nil {
				logger.Fatalf("unable to print diff analysis: %v", err)
			}

		} else if args[0] == "intersect" {
			analysisOne, analysisTwo, err := analyzer.HighlightAnalysis(graphs[0], graphs[1], 1)
			if err != nil {
				logger.Fatalf("Unable to generate intersect analysis: %v", err)
			}
			if err = printPathTable("Common Paths", analysisOne, analysisTwo); err != nil {
				logger.Fatalf("unable to print intersect analysis: %v", err)
			}
		} else if args[0] == "union" {
			analysisOne, analysisTwo, err := analyzer.HighlightAnalysis(graphs[0], graphs[1], 2)
			if err != nil {
				logger.Fatalf("unable to generate union analysis: %v", err)
			}
			if err = printPathTable("All Paths", analysisOne, analysisTwo); err != nil {
				logger.Fatalf("unable to print union analysis: %v", err)
			}
		}
	},
}

func printDiffedPathTable(diffs []analyzer.DiffedPath) error {

	table := tablewriter.NewWriter(os.Stdout)
	table.SetAutoWrapText(false)

	table.SetBorders(tablewriter.Border{Left: true, Bottom: true})

	table.SetNoWhiteSpace(true)

	table.SetColumnSeparator("\t\t")
	table.SetAutoMergeCells(false)

	table.SetHeader([]string{"Path Differences"})

	for _, diff := range diffs {
		var row []string

		for i, nodeOne := range diff.PathOne {

			if len(row) != 0 {
				row = append(row, "--->")
				table.SetColMinWidth(i+1, 90)
			} else {
				table.SetColMinWidth(i, 90)
			}

			if nodeOne.Attributes["nodeType"] == "Package" {
				s, err := analyzer.GetNodeString(1, nodeOne.Attributes["data"])
				if err != nil {
					return fmt.Errorf("unable to print diffs: %v", err)
				}
				row = append(row, s)

			} else if nodeOne.Attributes["nodeType"] == "DependencyPackage" {
				s, err := analyzer.GetNodeString(2, nodeOne.Attributes["data"])
				if err != nil {
					return fmt.Errorf("unable to print diffs: %v", err)
				}
				row = append(row, s)
			}
		}

		table.Append(row)
		row = []string{}

		for i, nodeOne := range diff.PathTwo {

			if len(row) != 0 {
				row = append(row, "--->")
				table.SetColMinWidth(i+1, 50)
			} else {
				table.SetColMinWidth(i, 50)
			}

			if nodeOne.Attributes["nodeType"] == "Package" {
				s, err := analyzer.GetNodeString(1, nodeOne.Attributes["data"])
				if err != nil {
					return fmt.Errorf("unable to print diffs: %v", err)
				}
				row = append(row, s)
			} else if nodeOne.Attributes["nodeType"] == "DependencyPackage" {
				s, err := analyzer.GetNodeString(2, nodeOne.Attributes["data"])
				if err != nil {
					return fmt.Errorf("unable to print diffs: %v", err)
				}
				row = append(row, s)
			}
		}
		table.Append(row)

		table.Append([]string{"================================="})

		row  = []string{}
		for i, diff := range diff.Diffs {
			
			if len(row) != 0 {
				row = append(row, "    ")
				table.SetColMinWidth(i+1, 50)
			}else{
				table.SetColMinWidth(i, 50)
			}
			
			row = append(row, strings.Join(diff, "\n"))
		}
		table.Append(row)


		table.Append([]string{"================================="})
	}

	
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.Render()
	return nil

}

func printPathTable(header string, analysisOne, analysisTwo [][]*analyzer.Node) error {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAutoWrapText(false)

	table.SetBorders(tablewriter.Border{Left: true, Bottom: true})

	table.SetNoWhiteSpace(true)

	table.SetColumnSeparator("\t\t")
	table.SetAutoMergeCells(false)

	table.SetHeader([]string{header})

	for _, pathOne := range analysisOne {
		var row []string
		for i, nodeOne := range pathOne {

			if len(row) != 0 {
				row = append(row, "--->")
				table.SetColMinWidth(i+1, 50)
			} else {
				table.SetColMinWidth(i, 50)
			}

			if nodeOne.Attributes["nodeType"] == "Package" {
				s, err := analyzer.GetNodeString(1, nodeOne.Attributes["data"])
				if err != nil {
					return fmt.Errorf("unable to print diffs: %v", err)
				}

				row = append(row, s)

			} else if nodeOne.Attributes["nodeType"] == "DependencyPackage" {
				s, err := analyzer.GetNodeString(2, nodeOne.Attributes["data"])
				if err != nil {
					return fmt.Errorf("unable to print diffs: %v", err)
				}
				row = append(row, s)
			}
		}
		table.Append(row)

	}

	for _, pathTwo := range analysisTwo {
		var row []string
		for i, nodeOne := range pathTwo {
			if len(row) != 0 {
				row = append(row, "--->")
				table.SetColMinWidth(i+1, 50)
			} else {
				table.SetColMinWidth(i, 50)
			}

			if nodeOne.Attributes["nodeType"] == "Package" {
				s, err := analyzer.GetNodeString(1, nodeOne.Attributes["data"])
				if err != nil {
					return fmt.Errorf("unable to print diffs: %v", err)
				}
				row = append(row, s)

			} else if nodeOne.Attributes["nodeType"] == "DependencyPackage" {
				s, err := analyzer.GetNodeString(2, nodeOne.Attributes["data"])
				if err != nil {
					return fmt.Errorf("unable to print diffs: %v", err)
				}
				row = append(row, s)
			}
		}
		table.Append(row)
	}

	table.Render()
	return nil
}

func hasSBOMToGraph(ctx context.Context, gqlclient graphql.Client, sboms []string, opts AnalyzeOpts) ([]graph.Graph[string, *analyzer.Node], error) {

	var hasSBOMResponseOne *model.HasSBOMsResponse
	var hasSBOMResponseTwo *model.HasSBOMsResponse
	var err error
	logger := logging.FromContext(ctx)

	if opts.URI {
		hasSBOMResponseOne, err = analyzer.FindHasSBOMBy(model.HasSBOMSpec{}, sboms[0], "", "", ctx, gqlclient)
		if err != nil {
			return []graph.Graph[string, *analyzer.Node]{}, fmt.Errorf("(uri)failed to lookup sbom: %v %v", sboms[0], err)
		}
		hasSBOMResponseTwo, err = analyzer.FindHasSBOMBy(model.HasSBOMSpec{}, sboms[1], "", "", ctx, gqlclient)
		if err != nil {
			return []graph.Graph[string, *analyzer.Node]{}, fmt.Errorf("(uri)failed to lookup sbom: %v %v", sboms[1], err)
		}
	} else if opts.PURL {
		hasSBOMResponseOne, err = analyzer.FindHasSBOMBy(model.HasSBOMSpec{}, "", sboms[0], "", ctx, gqlclient)
		if err != nil {
			return []graph.Graph[string, *analyzer.Node]{}, fmt.Errorf("(purl)failed to lookup sbom: %v %v", sboms[0], err)
		}
		hasSBOMResponseTwo, err = analyzer.FindHasSBOMBy(model.HasSBOMSpec{}, "", sboms[1], "", ctx, gqlclient)
		if err != nil {
			return []graph.Graph[string, *analyzer.Node]{}, fmt.Errorf("(purl)failed to lookup sbom: %v %v", sboms[1], err)
		}
	} else if opts.ID {
		hasSBOMResponseOne, err = analyzer.FindHasSBOMBy(model.HasSBOMSpec{}, "", "", sboms[0], ctx, gqlclient)
		if err != nil {
			return []graph.Graph[string, *analyzer.Node]{}, fmt.Errorf("(id)failed to lookup sbom: %v %v", sboms[0], err)
		}
		hasSBOMResponseTwo, err = analyzer.FindHasSBOMBy(model.HasSBOMSpec{}, "", "", sboms[1], ctx, gqlclient)
		if err != nil {
			return []graph.Graph[string, *analyzer.Node]{}, fmt.Errorf("(id)failed to lookup sbom: %v %v", sboms[1], err)
		}
	}

	if hasSBOMResponseOne == nil || hasSBOMResponseTwo == nil {
		return []graph.Graph[string, *analyzer.Node]{}, fmt.Errorf("failed to lookup sboms: nil")
	}

	if len(hasSBOMResponseOne.HasSBOM) == 0 || len(hasSBOMResponseTwo.HasSBOM) == 0 {
		return []graph.Graph[string, *analyzer.Node]{}, fmt.Errorf("failed to lookup sboms, one endpoint may not have sboms")
	}

	if len(hasSBOMResponseOne.HasSBOM) != 1 || len(hasSBOMResponseTwo.HasSBOM) != 1 {
		logger.Infof("Multiple sboms found for given purl, id or uri. Using first one")
	}
	hasSBOMOne := hasSBOMResponseOne.HasSBOM[0]
	hasSBOMTwo := hasSBOMResponseTwo.HasSBOM[0]

	//create graphs
	gOne, err := analyzer.MakeGraph(hasSBOMOne, opts.Metadata, opts.InclSoft, opts.InclDeps, opts.InclOccur, opts.Namespaces)
	if err != nil {
		logger.Fatalf(err.Error())
	}
	gTwo, err := analyzer.MakeGraph(hasSBOMTwo, opts.Metadata, opts.InclSoft, opts.InclDeps, opts.InclOccur, opts.Namespaces)
	if err != nil {
		logger.Fatalf(err.Error())
	}
	return []graph.Graph[string, *analyzer.Node]{
		gOne,
		gTwo,
	}, nil
}

func verifyAnalyzeFlags(slsas, sboms []string, errSlsa, errSbom error, uri, purl, id bool) error {

	if (errSlsa != nil && errSbom != nil) || (len(slsas) == 0 && len(sboms) == 0) {
		return fmt.Errorf("must specify slsa or sboms")
	}

	if len(slsas) > 0 && len(sboms) > 0 {
		return fmt.Errorf("must either specify slsa or sbom")
	}

	if errSlsa == nil && (len(slsas) <= 1 || len(slsas) > 2) && len(sboms) == 0 {
		return fmt.Errorf("must specify exactly two slsas to analyze, specified %v", len(slsas))
	}

	if errSbom == nil && (len(sboms) <= 1 || len(sboms) > 2) && len(slsas) == 0 {
		return fmt.Errorf("must specify exactly two sboms to analyze, specified %v", len(sboms))
	}

	if errSlsa == nil && len(slsas) == 2 {
		return fmt.Errorf("slsa diff to be implemented")
	}

	if !uri && !purl && !id {
		return fmt.Errorf("must provide one of --uri or --purl")
	}

	if uri && purl || uri && id || purl && id {
		return fmt.Errorf("must provide only one of --uri or --purl")
	}

	return nil
}

func readTwoSBOM(filename string) ([]graph.Graph[string, *analyzer.Node], error) {
	file, err := os.Open(filename)
	if err != nil {
		return []graph.Graph[string, *analyzer.Node]{}, fmt.Errorf("error opening test file")
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return []graph.Graph[string, *analyzer.Node]{}, fmt.Errorf("error reading test file")
	}
	var sboms []model.HasSBOMsHasSBOM

	err = json.Unmarshal(data, &sboms)
	if err != nil {
		return []graph.Graph[string, *analyzer.Node]{}, fmt.Errorf("error unmarshaling JSON")
	}

	graphOne, errOne := analyzer.MakeGraph(sboms[0], false, false, false, false, false)

	graphTwo, errTwo := analyzer.MakeGraph(sboms[1], false, false, false, false, false)

	if errOne != nil || errTwo != nil {
		return []graph.Graph[string, *analyzer.Node]{}, fmt.Errorf("error making graph %v %v", errOne.Error(), errTwo.Error())
	}

	return []graph.Graph[string, *analyzer.Node]{graphOne, graphTwo}, nil

}

func init() {

	analyzeCmd.PersistentFlags().StringSlice("sboms", []string{}, "two sboms to analyze")
	analyzeCmd.PersistentFlags().StringSlice("slsa", []string{}, "two slsa to analyze")
	analyzeCmd.PersistentFlags().Bool("uri", false, "input is a URI")
	analyzeCmd.PersistentFlags().Bool("purl", false, "input is a pURL")
	analyzeCmd.PersistentFlags().Bool("id", false, "input is an Id")
	analyzeCmd.PersistentFlags().Bool("metadata", false, "Compare SBOM metadata")
	analyzeCmd.PersistentFlags().Bool("incl-soft", false, "Compare Included Softwares")
	analyzeCmd.PersistentFlags().Bool("incl-deps", false, "Compare Included Dependencies")
	analyzeCmd.PersistentFlags().Bool("incl-occur", false, "Compare Included Occurrences")
	analyzeCmd.PersistentFlags().Bool("namespaces", false, "Compare Package Namespaces")
	analyzeCmd.PersistentFlags().Bool("dot", false, "create diff dot file")
	analyzeCmd.PersistentFlags().Bool("all", false, " lists all")
	analyzeCmd.PersistentFlags().Int("maxprint", 20, "max number of items to print")
	analyzeCmd.PersistentFlags().String("test", "", "test file with sbom")

	rootCmd.AddCommand(analyzeCmd)
}
