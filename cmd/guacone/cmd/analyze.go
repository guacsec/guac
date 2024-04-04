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

  "github.com/Khan/genqlient/graphql"
  "github.com/guacsec/guac/pkg/logging"
  "github.com/spf13/cobra"
  "github.com/spf13/viper"
  analysis "github.com/guacsec/guac/pkg/guacanalyze"
)

const PRINT_MAX = 20

var analyzeCmd = &cobra.Command{
  Use:     "analyze <operation> <sboms> [flags] ",
  Short:   "guacanalyze is a CLI tool tailored for comparing, intersecting, and merging Software Bill of Materials (SBOMs) within GUAC",
  Long:  `Diff Analysis: Compare two SBOMs to identify differences in their software components, versions, and dependencies.
  Intersection Analysis: Determine the intersection of two SBOMs, highlighting common software components shared between them.
  Union Analysis: Combine two SBOMs to create a unified SBOM, merging software component lists while maintaining version integrity.`,
  Example: `
  Ingest the SBOMs to analyze:
  $ guacone collect files guac-data-main/docs/spdx/syft-spdx-k8s.gcr.io-kube-apiserver.v1.24.4.json
  $ guacone collect files guac-data-main/docs/spdx/spdx_vuln.json 
  Difference
  $ guacanalyze analyze --diff --uri --sboms=https://anchore.com/syft/image/ghcr.io/guacsec/vul-image-latest-6fd9de7b-9bec-4ae7-99d9-4b5e5ef6b869,https://anchore.com/syft/image/k8s.gcr.io/kube-apiserver-v1.24.4-b15339bc-a146-476e-a789-6a65e4e22e54
  Union
  $ guacanalyze analyze --union --uri --sboms=https://anchore.com/syft/image/ghcr.io/guacsec/vul-image-latest-6fd9de7b-9bec-4ae7-99d9-4b5e5ef6b869,https://anchore.com/syft/image/k8s.gcr.io/kube-apiserver-v1.24.4-b15339bc-a146-476e-a789-6a65e4e22e54
  Intersection

  $ guacanalyze analyze --intersect --uri --sboms=https://anchore.com/syft/image/ghcr.io/guacsec/vul-image-latest-6fd9de7b-9bec-4ae7-99d9-4b5e5ef6b869,https://anchore.com/syft/image/k8s.gcr.io/kube-apiserver-v1.24.4-b15339bc-a146-476e-a789-6a65e4e22e54
  `,
  Run: func(cmd *cobra.Command, args []string) {
    ctx := logging.WithLogger(context.Background())
    httpClient := http.Client{}
    gqlclient := graphql.NewClient(viper.GetString("gql-addr"), &httpClient)


    //get necessary flags
    dot, _ := cmd.Flags().GetBool("dot")
    intersect, _ := cmd.Flags().GetBool("intersect")
    diff, _ := cmd.Flags().GetBool("diff")
    union, _ := cmd.Flags().GetBool("union")
    all, _ := cmd.Flags().GetBool("all")
    maxprint, _ := cmd.Flags().GetInt("maxprint")


    if diff && intersect && union || diff && intersect || diff && union || intersect && union {
      fmt.Println("Must specify only one of --diff, --intersect, --union")
      return
    }

    //create graphs
    graphs := analysis.HasSBOMToGraph(cmd, ctx, gqlclient)

    if diff {
      analysisGraph, analysisList := analysis.HighlightAnalysis(graphs[0], graphs[1], 0)
      analysis.GenerateAnalysisOutput(analysisGraph, analysisList, all, dot, maxprint, 0 ,gqlclient)
    } else if intersect {
      analysisGraph, analysisList := analysis.HighlightAnalysis(graphs[0], graphs[1], 1)
      analysis.GenerateAnalysisOutput(analysisGraph, analysisList, all, dot, maxprint, 1,gqlclient)
    } else if union {
      analysisGraph, analysisList := analysis.HighlightAnalysis(graphs[0], graphs[1], 2)
      analysis.GenerateAnalysisOutput(analysisGraph, analysisList, all, dot, maxprint, 2,gqlclient)
    } else {
      fmt.Println("Must specify one of --diff, --intersect, --union")
      return
    }
  },
}



func init() {

  rootCmd.PersistentFlags().Bool("intersect", false, "compute intesection of given sboms")
  rootCmd.PersistentFlags().Bool("union", false, "compute union of given sboms")
  rootCmd.PersistentFlags().Bool("diff", false, "compute diff of given sboms")

  rootCmd.PersistentFlags().StringSlice("sboms", []string{}, "two sboms to analyze")
  rootCmd.PersistentFlags().StringSlice("slsa", []string{}, "two slsa to analyze")
  rootCmd.PersistentFlags().Bool("uri", false, "input is a URI")
  rootCmd.PersistentFlags().Bool("purl", false, "input is a pURL")
  rootCmd.PersistentFlags().Bool("id", false, "input is an Id")
  rootCmd.PersistentFlags().Bool("metadata", false, "Compare SBOM metadata")
  rootCmd.PersistentFlags().Bool("inclSoft", false, "Compare Included Softwares")
  rootCmd.PersistentFlags().Bool("inclDeps", false, "Compare Included Dependencies")
  rootCmd.PersistentFlags().Bool("inclOccur", false, "Compare Included Occurrences")
  rootCmd.PersistentFlags().Bool("namespaces", false, "Compare Package Namespaces")
  rootCmd.PersistentFlags().Bool("dot", false, "create diff dot file")

  rootCmd.PersistentFlags().Bool("list", false, "List Similar SBOMs given a filter(ID(string), Algorithm(string), Digest(string), DownloadLocation(string), Origin(string), Uri(string), Collector(string))")
  rootCmd.PersistentFlags().String("ID", "", "--list --ID <ID Filter>")
  rootCmd.PersistentFlags().String("Algorithm", "", "--list --Algorithm <Algorithm Filter>")
  rootCmd.PersistentFlags().String("Digest", "", "--list --Digest<Digest Filter>")
  rootCmd.PersistentFlags().String("Downloc", "", "--list --DownLoc <DownloadLocation Filter>")
  rootCmd.PersistentFlags().String("Origin", "", "--list --Origin <Origin Filter>")
  rootCmd.PersistentFlags().String("URI", "", "--list --URI <URI Filter>")
  rootCmd.PersistentFlags().String("Collector", "", "--list --Collector <Collector Filter>")
  rootCmd.PersistentFlags().Bool("all", false, "--all, lists all")
  rootCmd.PersistentFlags().Int("maxprint", PRINT_MAX, "max number of similar sboms to print")
  rootCmd.AddCommand(analyzeCmd)

}