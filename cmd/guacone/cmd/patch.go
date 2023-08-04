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
	"time"

	"github.com/Khan/genqlient/graphql"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/cli"
	analysis "github.com/guacsec/guac/pkg/guacanalytics"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type queryPatchOptions struct {
	graphqlEndpoint string
	startPurl       string
	stopPurl        string
	depth           int
	sampleData      bool
}

var (
	tm, _       = time.Parse(time.RFC3339, "2023-08-02T17:45:50.52Z")
	sampleGraph = assembler.IngestPredicates{
		IsDependency: []assembler.IsDependencyIngest{
			{
				Pkg: &model.PkgInputSpec{
					Type:      "1pkgType",
					Namespace: ptrfrom.String("1pkgNamespace"),
					Name:      "1pkgName",
					Version:   ptrfrom.String("1.19.0"),
				},
				DepPkg: &model.PkgInputSpec{
					Type:      "3pkgType",
					Namespace: ptrfrom.String("3pkgNamespace"),
					Name:      "3pkgName",
					Version:   ptrfrom.String("1.19.0"),
				},
				IsDependency: &model.IsDependencyInputSpec{
					VersionRange:   ">=1.19.0",
					DependencyType: model.DependencyTypeDirect,
					Justification:  "test justification one",
					Origin:         "Demo ingestion",
					Collector:      "Demo ingestion",
				},
			},
		},

		IsOccurrence: []assembler.IsOccurrenceIngest{
			{
				Pkg: &model.PkgInputSpec{
					Type:      "1pkgType",
					Namespace: ptrfrom.String("1pkgNamespace"),
					Name:      "1pkgName",
					Version:   ptrfrom.String("1.19.0"),
				},
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "1testArtifactAlgorithm",
					Digest:    "1testArtifactDigest",
				},
				IsOccurrence: &model.IsOccurrenceInputSpec{
					Justification: "connect 1pkg and 1artifact",
				},
			},
			{
				Pkg: &model.PkgInputSpec{
					Type:      "2pkgType",
					Namespace: ptrfrom.String("2pkgNamespace"),
					Name:      "2pkgName",
					Version:   ptrfrom.String("1.19.0"),
				},
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "2testArtifactAlgorithm",
					Digest:    "2testArtifactDigest",
				},
				IsOccurrence: &model.IsOccurrenceInputSpec{
					Justification: "connect 2pkg and 2artifact",
				},
			},
		},
		HasSlsa: []assembler.HasSlsaIngest{
			{
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "2testArtifactAlgorithm",
					Digest:    "2testArtifactDigest",
				},
				Builder: &model.BuilderInputSpec{
					Uri: "testUri",
				},
				Materials: []model.ArtifactInputSpec{{
					Algorithm: "1testArtifactAlgorithm",
					Digest:    "1testArtifactDigest",
				}},
				HasSlsa: &model.SLSAInputSpec{
					BuildType:   "testBuildType",
					SlsaVersion: "testSlsaVersion",
					SlsaPredicate: []model.SLSAPredicateInputSpec{
						{Key: "slsa.testKey", Value: "testValue"},
					},
				},
			},
		},
		PointOfContact: []assembler.PointOfContactIngest{
			{
				Pkg: &model.PkgInputSpec{
					Type:      "1pkgType",
					Namespace: ptrfrom.String("1pkgNamespace"),
					Name:      "1pkgName",
					Version:   ptrfrom.String("1.19.0"),
				},
				PkgMatchFlag: model.MatchFlags{
					Pkg: model.PkgMatchTypeSpecificVersion,
				},
				PointOfContact: &model.PointOfContactInputSpec{
					Email:         "testEmail1",
					Info:          "testInfo",
					Since:         tm,
					Justification: "testJustification",
					Origin:        "testOrigin",
					Collector:     "testCollector",
				},
			},
			{
				Pkg: &model.PkgInputSpec{
					Type:      "2pkgType",
					Namespace: ptrfrom.String("2pkgNamespace"),
					Name:      "2pkgName",
					Version:   ptrfrom.String("1.19.0"),
				},
				PkgMatchFlag: model.MatchFlags{
					Pkg: model.PkgMatchTypeSpecificVersion,
				},
				PointOfContact: &model.PointOfContactInputSpec{
					Email:         "testEmail2",
					Info:          "testInfo",
					Since:         tm,
					Justification: "testJustification",
					Origin:        "testOrigin",
					Collector:     "testCollector",
				},
			},
		},
	}
)

var queryPatchCmd = &cobra.Command{
	Use:   "patch plan [flags] purl",
	Short: "query which packages are affected by the vulnerability associated with specified packageName or packageVersion",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		opts, err := validateQueryPatchFlags(
			viper.GetString("gql-addr"),
			viper.GetString("start-purl"),
			viper.GetString("stop-purl"),
			viper.GetInt("search-depth"),
			viper.GetBool("sample-data"),
			args,
		)

		if err != nil {
			fmt.Printf("unable to validate flags: %s\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		httpClient := http.Client{}
		gqlClient := graphql.NewClient(opts.graphqlEndpoint, &httpClient)

		var startID string
		var stopID *string
		stopID = nil
		if opts.sampleData {
			err = analysis.IngestTestData(ctx, gqlClient, sampleGraph)

			if err != nil {
				fmt.Printf("error ingesting test data: %s\n", err)
			}
			getPackageIDsValues, err := analysis.GetPackageIDs(ctx, gqlClient, ptrfrom.String("3pkgType"), "3pkgNamespace", "3pkgName", ptrfrom.String("1.19.0"), true, false)

			startID = *getPackageIDsValues[0]
			if err != nil {
				logger.Errorf("error get start pkg for simple data: %s", err)
			}

		} else {
			startID, err = getPkgID(ctx, gqlClient, opts.startPurl)

			if err != nil {
				logger.Errorf("error getting start pkg from purl inputted %s \n", err)
				os.Exit(1)
			}

			if opts.stopPurl != "" {
				stopPkg, err := getPkgID(ctx, gqlClient, opts.stopPurl)

				if err != nil {
					logger.Errorf("error getting stop pkg from purl inputted %s\n", err)
				}

				stopID = &stopPkg
			}

		}

		bfsMap, path, err := analysis.SearchDependenciesFromStartNode(ctx, gqlClient, startID, stopID, opts.depth)

		if err != nil {
			logger.Errorf("error searching dependencies-- %s\n", err)
			os.Exit(1)
		}

		frontiers, infoNodes, err := analysis.ToposortFromBfsNodeMap(ctx, gqlClient, bfsMap)

		if err != nil {
			logger.Errorf("error toposorting-- %s\n", err)
			os.Exit(1)
		}

		// TODO: print out nodes themselves, not just IDs
		poc := []string{}
		for level := 0; level < len(frontiers); level++ {
			frontierList := frontiers[level]
			allNodes := []string{}
			for _, id := range frontierList {
				path = append(path, id)
				allNodes = append(allNodes, id)
			}
			fmt.Printf("\n---FRONTIER LEVEL %d---\n", level)
			poc = append(poc, printNodesInfo(ctx, gqlClient, bfsMap, allNodes)...)
		}

		fmt.Println("\n---INFO NODES---")
		if len(infoNodes) == 0 {
			fmt.Println("no info nodes found")
		} else {
			poc = append(poc, printNodesInfo(ctx, gqlClient, bfsMap, infoNodes)...)
		}

		fmt.Printf("\n---POINTS OF CONTACT---")
		if len(poc) == 0 {
			fmt.Println("\nno POCs found")
		} else {
			for _, id := range poc {
				fmt.Printf("\n%s: %s", id, makePOCPretty(bfsMap[id].PointOfContact))
			}
		}

		fmt.Printf("\n\n---SUBGRAPH VISUALIZER URL--- \nhttp://localhost:3000/?path=%s\n", strings.Join(removeDuplicateValuesFromPath(path), `,`))
	},
}

func printNodesInfo(ctx context.Context, gqlClient graphql.Client, bfsMap map[string]analysis.BfsNode, nodes []string) []string {
	poc := []string{}
	for _, id := range nodes {
		node, err := model.Node(ctx, gqlClient, id)

		if err != nil {
			fmt.Printf("error: %s \n", err)
		}

		var pretty string
		switch node := node.Node.(type) {
		case *model.NodeNodePackage:
			if bfsMap[id].Type == analysis.PackageName {
				pretty = makePkgPretty(*node, false)
			} else {
				pretty = makePkgPretty(*node, true)
			}
		case *model.NodeNodeSource:
			pretty = makeSrcPretty(*node)
		case *model.NodeNodeArtifact:
			pretty = makeArtifactPretty(*node)
		}

		fmt.Printf("%s: %s\n", id, pretty)

		if bfsMap[id].PointOfContact.Email != "" {
			poc = append(poc, id)
		}
	}
	return poc
}

func makePOCPretty(poc model.AllPointOfContact) string {
	return fmt.Sprintf("id- %s | email- %s | info- %s | collector- %s | justification- %s | origin- %s | since- %s", poc.Id, poc.Email, poc.Info, poc.Collector, poc.Justification, poc.Origin, poc.Since)
}

func makePkgPretty(pkg model.NodeNodePackage, version bool) string {
	pkgString := fmt.Sprintf("pkg:%s/%s/%s", pkg.Type, pkg.Namespaces[0].Namespace, pkg.Namespaces[0].Names[0].Name)

	if version {
		return fmt.Sprintf("%s@%s", pkgString, pkg.Namespaces[0].Names[0].Versions[0].Version)
	}

	return pkgString
}

func makeSrcPretty(src model.NodeNodeSource) string {
	return fmt.Sprintf("src:%s/%s/%s", src.Type, src.Namespaces[0].Namespace, src.Namespaces[0].Names[0].Name)
}

func makeArtifactPretty(artifact model.NodeNodeArtifact) string {
	return fmt.Sprintf("artifact: algorithm-%s | digest:%s", artifact.Algorithm, artifact.Digest)
}

func getPkgID(ctx context.Context, gqlClient graphql.Client, purl string) (string, error) {
	pkgInput, err := helpers.PurlToPkg(purl)

	if err != nil {
		return "", err
	}

	var pkgFilter model.PkgSpec
	version := false

	if pkgInput.Version != nil && *pkgInput.Version != "" {
		pkgFilter = model.PkgSpec{
			Type:      &pkgInput.Type,
			Namespace: pkgInput.Namespace,
			Name:      &pkgInput.Name,
			Version:   pkgInput.Version,
		}
		version = true
	} else {
		pkgFilter = model.PkgSpec{
			Type:      &pkgInput.Type,
			Namespace: pkgInput.Namespace,
			Name:      &pkgInput.Name,
		}
	}

	pkgResponse, err := model.Packages(ctx, gqlClient, pkgFilter)

	if err != nil || len(pkgResponse.Packages) == 0 {
		return "", fmt.Errorf("error finding package with given purl: %s", purl)
	}

	if version {
		return pkgResponse.Packages[0].Namespaces[0].Names[0].Versions[0].Id, nil
	}
	return pkgResponse.Packages[0].Namespaces[0].Names[0].Id, nil
}

func validateQueryPatchFlags(graphqlEndpoint, startPurl string, stopPurl string, depth int, sampleData bool, args []string) (queryPatchOptions, error) {
	var opts queryPatchOptions
	opts.graphqlEndpoint = graphqlEndpoint
	opts.startPurl = startPurl
	opts.stopPurl = stopPurl
	opts.depth = depth
	opts.sampleData = sampleData

	return opts, nil
}

func init() {
	set, err := cli.BuildFlags([]string{"start-purl", "stop-purl", "search-depth", "sample-data"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup flag: %s", err)
		os.Exit(1)
	}
	queryPatchCmd.Flags().AddFlagSet(set)
	if err := viper.BindPFlags(queryPatchCmd.Flags()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to bind flags: %s", err)
		os.Exit(1)
	}

	queryCmd.AddCommand(queryPatchCmd)
}
