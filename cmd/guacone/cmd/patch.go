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
	analysis "github.com/guacsec/guac/pkg/guacanalytics"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type queryPatchOptions struct {
	graphqlEndpoint       string
	startPurl             string
	stopPurl              string
	depth                 int
	isPackageVersionStart bool
	isPackageVersionStop  bool
}

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
			viper.GetBool("is-pkg-version-start"),
			viper.GetBool("is-pkg-version-stop"),
			args,
		)

		if err != nil {
			logger.Fatalf("unable to validate flags: %s\n", err)
		}

		httpClient := http.Client{}
		gqlClient := graphql.NewClient(opts.graphqlEndpoint, &httpClient)

		var startID string
		var stopID *string
		stopID = nil

		startID, err = getPkgID(ctx, gqlClient, opts.startPurl, opts.isPackageVersionStart)

		if err != nil {
			logger.Fatalf("error getting start pkg from purl inputted %s \n", err)
		}

		if opts.stopPurl != "" {
			stopPkg, err := getPkgID(ctx, gqlClient, opts.stopPurl, opts.isPackageVersionStop)

			if err != nil {
				logger.Fatalf("error getting stop pkg from purl inputted %s\n", err)
			}

			stopID = &stopPkg

		}

		bfsMap, path, err := analysis.SearchDependenciesFromStartNode(ctx, gqlClient, startID, stopID, opts.depth)

		if err != nil {
			logger.Fatalf("error searching dependencies-- %s\n", err)
		}

		frontiers, infoNodes, err := analysis.ToposortFromBfsNodeMap(ctx, gqlClient, bfsMap)

		if err != nil {
			logger.Fatalf("error toposorting-- %s\n", err)
		}

		var poc []string
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

		fmt.Printf("\n---INFO NODES---\n")
		if len(infoNodes) == 0 {
			fmt.Printf("no info nodes found\n")
		} else {
			poc = append(poc, printNodesInfo(ctx, gqlClient, bfsMap, infoNodes)...)
		}

		fmt.Printf("\n---POINTS OF CONTACT---")
		if len(poc) == 0 {
			fmt.Printf("\nno POCs found\n")
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

func makePkgPretty(pkg model.NodeNodePackage, isPackageVersion bool) string {
	version := ""
	subpath := ""
	var qualifiers []string

	if isPackageVersion {
		version = pkg.Namespaces[0].Names[0].Versions[0].Version

		subpath = pkg.Namespaces[0].Names[0].Versions[0].Subpath

		for _, qualifier := range pkg.Namespaces[0].Names[0].Versions[0].Qualifiers {
			qualifiers = append(qualifiers, qualifier.Key, qualifier.Value)
		}

	}

	pkgString := helpers.PkgToPurl(pkg.Type, pkg.Namespaces[0].Namespace, pkg.Namespaces[0].Names[0].Name, version, subpath, qualifiers)

	return pkgString
}

func makeSrcPretty(src model.NodeNodeSource) string {
	return fmt.Sprintf("src:%s/%s/%s", src.Type, src.Namespaces[0].Namespace, src.Namespaces[0].Names[0].Name)
}

func makeArtifactPretty(artifact model.NodeNodeArtifact) string {
	return fmt.Sprintf("artifact: algorithm-%s | digest:%s", artifact.Algorithm, artifact.Digest)
}

func getPkgID(ctx context.Context, gqlClient graphql.Client, purl string, isPackageVersion bool) (string, error) {
	pkgInput, err := helpers.PurlToPkg(purl)

	if err != nil {
		return "", fmt.Errorf("error getting pkg ID: %s", err)
	}

	var pkgFilter model.PkgSpec
	version := false

	if isPackageVersion {
		pkgQualifierFilter := []model.PackageQualifierSpec{}
		for _, qualifier := range pkgInput.Qualifiers {
			pkgQualifierFilter = append(pkgQualifierFilter, model.PackageQualifierSpec{
				Key:   qualifier.Key,
				Value: &qualifier.Value,
			})
		}
		pkgFilter = model.PkgSpec{
			Type:       &pkgInput.Type,
			Namespace:  pkgInput.Namespace,
			Name:       &pkgInput.Name,
			Version:    pkgInput.Version,
			Subpath:    pkgInput.Subpath,
			Qualifiers: pkgQualifierFilter,
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
		return "", fmt.Errorf("error finding package with given purl (may have set is-pkg-version incorrectly): %s", purl)
	}

	if version {
		return pkgResponse.Packages[0].Namespaces[0].Names[0].Versions[0].Id, nil
	}
	return pkgResponse.Packages[0].Namespaces[0].Names[0].Id, nil
}

func validateQueryPatchFlags(graphqlEndpoint, startPurl string, stopPurl string, depth int, isPackageVersionStart bool, isPackageVersionStop bool, args []string) (queryPatchOptions, error) {
	var opts queryPatchOptions
	opts.startPurl = startPurl

	if _, err := helpers.PurlToPkg(startPurl); startPurl != "" && err != nil {
		return opts, fmt.Errorf("expected input to be purl")
	}

	opts.graphqlEndpoint = graphqlEndpoint
	opts.stopPurl = stopPurl
	opts.depth = depth
	opts.isPackageVersionStart = isPackageVersionStart
	opts.isPackageVersionStop = isPackageVersionStop

	return opts, nil
}

func init() {
	set, err := cli.BuildFlags([]string{"start-purl", "stop-purl", "search-depth", "is-pkg-version-start", "is-pkg-version-stop"})
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
