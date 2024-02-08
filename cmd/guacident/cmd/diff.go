//
// Copyright 2022 The GUAC Authors.
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
	"reflect"
	"github.com/Khan/genqlient/graphql"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type Node struct {
	Value interface{}
}

type Graph map[Node][]Node

func (g Graph) AddEdge(source, target Node) {
	g[source] = append(g[source], target)
}

// diffCmd represents the diff command
var diffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Get a unified tree diff for two given SBOMS",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {

		boms, _ := cmd.Flags().GetStringSlice("boms")
		if len(boms) != 2 {
			fmt.Errorf("Must provide only two sboms to find the diff between")
			os.Exit(1)
		}
		lcs, _ := cmd.Flags().GetBool("lcs")
		mhd, _ := cmd.Flags().GetBool("mhd")
		uri, _ := cmd.Flags().GetBool("uri")
		purl, _ := cmd.Flags().GetBool("purl")

		if !uri && !purl {
			fmt.Errorf("Must provide one of --uri or --purl")
			os.Exit(1)
		}

		if !lcs && !mhd {
			fmt.Errorf("Must provide one of --lcs or --mhd")
			os.Exit(1)
		}

		if uri && purl {
			fmt.Errorf("Must provide only one of --uri or --purl")
			os.Exit(1)
		}

		if lcs && mhd {
			fmt.Errorf("Must provide only one of --lcs or --mhd")
			os.Exit(1)
		}

		ctx := logging.WithLogger(context.Background())
		httpClient := http.Client{}
		gqlclient := graphql.NewClient(viper.GetString("gql-addr"), &httpClient)
		var hasSBOMResponseOne *model.HasSBOMsResponse

		var hasSBOMResponseTwo *model.HasSBOMsResponse
		var err error
		if uri {
			hasSBOMResponseOne, err = findHasSBOMBy("", boms[0], "", "", "", "", "", "", ctx, gqlclient)
			if err != nil {
				fmt.Errorf("failed to lookup sbom: %s %v", boms[0], err)
				return
			}

			hasSBOMResponseTwo, err = findHasSBOMBy("", boms[1], "", "", "", "", "", "", ctx, gqlclient)
			if err != nil {
				fmt.Errorf("failed to lookup sbom: %s %v", boms[1], err)
				return
			}
		} else if purl {

			hasSBOMResponseTwo, err = findHasSBOMBy("", "", boms[0], "", "", "", "", "", ctx, gqlclient)
			if err != nil {
				fmt.Errorf("failed to lookup sbom: %s %v", boms[0], err)
				return
			}
			hasSBOMResponseTwo, err = findHasSBOMBy("", "", boms[1], "", "", "", "", "", ctx, gqlclient)
			if err != nil {
				fmt.Errorf("failed to lookup sbom: %s %v", boms[1], err)
				return
			}
		}
		G1 := make(Graph)
		G2 := make(Graph)

		hasSBOMResponseToGraph(reflect.ValueOf(hasSBOMResponseOne), G1)
		hasSBOMResponseToGraph(reflect.ValueOf(hasSBOMResponseTwo), G2)

		if err = performDiff(G1, G2, lcs, mhd ); err != nil {
			fmt.Errorf("failed to perform diff with error: %v", err)
			return
		}
	},
}

func hasSBOMResponseToGraph(structValue reflect.Value, graph Graph) {
	for i := 0; i < structValue.NumField(); i++ {
		field := structValue.Field(i)
		node := Node{Value: field.Interface()}

		graph[node] = make([]Node, 0)

		switch field.Kind() {
		case reflect.Struct:
			hasSBOMResponseToGraph(field, graph)
		case reflect.Slice, reflect.Array:
			for j := 0; j < field.Len(); j++ {
				element := field.Index(j)
				if element.Kind() == reflect.Struct {
					hasSBOMResponseToGraph(element, graph)
				}
			}
		}
	}
}  

func performDiff(G1, G2 Graph, lcs bool, mhd bool) error{
	if(lcs){

	}else if (mhd){

	}
	return nil
}



func init() {
	rootCmd.AddCommand(diffCmd)
	rootCmd.PersistentFlags().StringSlice("boms", []string{}, "two sboms to find the diff between")
	rootCmd.PersistentFlags().Bool("lcs", false, "use the Longest-Common-Subsequence algorithm to find the diff")
	rootCmd.PersistentFlags().Bool("mhd", false, "use the MH-Diff algorithm to find the diff")
	rootCmd.PersistentFlags().Bool("uri", false, "input is a URI")
	rootCmd.PersistentFlags().Bool("purl", false, "input is a pURL")
}
