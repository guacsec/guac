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
	"time"

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

func init() {
	rootCmd.AddCommand(diffCmd)
	rootCmd.PersistentFlags().StringSlice("boms", []string{}, "two sboms to find the diff between")
	rootCmd.PersistentFlags().Bool("uri", false, "input is a URI")
	rootCmd.PersistentFlags().Bool("purl", false, "input is a pURL")
	rootCmd.PersistentFlags().Bool("wide", false, "show differences in color")
}

var diffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Get a unified tree diff for two given SBOMS",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		boms, err := cmd.Flags().GetStringSlice("boms")
		if err!= nil {
			fmt.Println("Must provide two sboms to find the diff between")
			os.Exit(1)
		}

		if len(boms) < 2 {
			fmt.Println("Must provide two sboms to find the diff between")
			fmt.Println(boms)
			os.Exit(1)
		}else if len(boms) > 2{
			fmt.Println("Must provide only two sboms to find the diff between")
			os.Exit(1)
		}

		uri, _ := cmd.Flags().GetBool("uri")
		purl, _ := cmd.Flags().GetBool("purl")
		wide, _ := cmd.Flags().GetBool("wide")

		if !uri && !purl {
			fmt.Println("Must provide one of --uri or --purl")
			os.Exit(1)
		}


		if uri && purl {
			fmt.Println("Must provide only one of --uri or --purl")
			os.Exit(1)
		}


		ctx := logging.WithLogger(context.Background())
		httpClient := http.Client{}
		gqlclient := graphql.NewClient(viper.GetString("gql-addr"), &httpClient)
		var hasSBOMResponseOne *model.HasSBOMsResponse

		var hasSBOMResponseTwo *model.HasSBOMsResponse
	
		if uri {
			hasSBOMResponseOne, err = findHasSBOMBy(boms[0],"",  ctx, gqlclient)
			if err != nil {
				fmt.Println("failed to lookup sbom: %s %v", boms[0], err)
				return
			}

			hasSBOMResponseTwo, err = findHasSBOMBy( boms[1],"",  ctx, gqlclient)
			if err != nil {
				fmt.Println("failed to lookup sbom: %s %v", boms[1], err)
				return
			}
		} else if purl {

			hasSBOMResponseTwo, err = findHasSBOMBy( "", boms[0],  ctx, gqlclient)
			if err != nil {
				fmt.Println("failed to lookup sbom: %s %v", boms[0], err)
				return
			}
			hasSBOMResponseTwo, err = findHasSBOMBy( "", boms[1], ctx, gqlclient)
			if err != nil {
				fmt.Println("failed to lookup sbom: %s %v", boms[1], err)
				return
			}
		}
		if hasSBOMResponseOne == nil || hasSBOMResponseTwo == nil {
			fmt.Println("failed to lookup sboms")
			return
		}
		if len(hasSBOMResponseOne.HasSBOM) == 0 || len(hasSBOMResponseTwo.HasSBOM) == 0 {
			fmt.Println("Failed to lookup sboms, one endpoint may not have sboms")
			return
		}
		if len(hasSBOMResponseOne.HasSBOM) != 1 || len(hasSBOMResponseTwo.HasSBOM) != 1 {
			fmt.Println("Warning: Multiple sboms found for given purl or uri. Using first one")
		}

		nodeOne := Node{Value: hasSBOMResponseOne.HasSBOM[0]}
		nodeTwo := Node{Value: hasSBOMResponseTwo.HasSBOM[0]}

		hasSBOMResponseToGraph(reflect.ValueOf(hasSBOMResponseOne.HasSBOM[0]), &nodeOne)
		hasSBOMResponseToGraph(reflect.ValueOf(hasSBOMResponseTwo.HasSBOM[0]), &nodeTwo)

		if (!wide) {
			//just print the diff result
			fmt.Println(rawCompareGraphs(&nodeOne, &nodeTwo))
			return
		}

		performDiff(&nodeOne, &nodeTwo)

	},
}

func rawCompareGraphs(node1, node2 *Node) string {
	if !reflect.DeepEqual(node1, node2) {
		return "SBOMs differ"
	}
	return "SBOMs are identical"
}

// This function recursively traverses the fields of a struct using reflection and converts them into nodes of a graph. 
// It handles nested structs and arrays within the main struct.
func hasSBOMResponseToGraph(data reflect.Value, head *Node) {
	node := Node{Value: data.Interface(), tag: data.Type().Name()}
	head.neighbours = append(head.neighbours, &node)
	
	//base case
	if data.Kind() != reflect.Array && data.Kind() != reflect.Slice && data.Kind() != reflect.Struct {
		//just add a neighbour and return
		return
	}
	// edge base case for time.Time to not go into recursion, while being a "struct"
	if data.Kind() == reflect.Struct && data.Type() == reflect.TypeOf(time.Time{}) {
		return
	}

	//if we have a struct, we need to go over its fields
	//update head to be the last element of the neighbours slice
	newHead := head.neighbours[len(head.neighbours)-1]
	//first input is the HasSBOMsHasSBOM struct, we go over its fields
	var length = 0
	var field reflect.Value
	if data.Kind() == reflect.Struct {
		length = data.NumField()
	}else if data.Kind() == reflect.Array || data.Kind() == reflect.Slice {
		length = data.Len()
	}
	for i := 0; i < length; i++ {
		if data.Kind() == reflect.Struct {
			field = data.Field(i)
		}else if data.Kind() == reflect.Array || data.Kind() == reflect.Slice {
			field = data.Index(i)
		}
			hasSBOMResponseToGraph(field, newHead)
        }
}
func performDiff(nodeOne, nodeTwo *Node){
	if reflect.DeepEqual(nodeOne,Node{}) && reflect.DeepEqual(nodeTwo,Node{}) {
		return
	}

	if len(nodeOne.neighbours) != len(nodeTwo.neighbours) {
		fmt.Println("Neighbour node count mismatch!")
	}

	
    for i := 0; i < len(nodeOne.neighbours) || i < len(nodeTwo.neighbours); i++ {
        if i < len(nodeOne.neighbours) && i < len(nodeTwo.neighbours) {
            performDiff(nodeOne.neighbours[i], nodeOne.neighbours[i])
        } else if i < len(nodeOne.neighbours) {
            fmt.Printf("SBOM 1 extra %+v\n", nodeOne.neighbours[i].tag)
        } else {
            fmt.Printf("SBOM 2 extra %+v\n", nodeTwo.neighbours[i].tag)
        }
    }
}
//helpers
func printNode(node *Node, name string) {
	if node == nil {
		return
	}
	fmt.Printf("%s %s\n", name, node.tag)
}
func printTree(node *Node, level int) {
	if node == nil {
		return
	}

	// Print the current node's value with indentation
	for i := 0; i < level; i++ {
		fmt.Print("\t")
	}
	fmt.Println(node.tag, " ", node.Value)

	// Recursively print the child nodes
	for _, child := range node.neighbours {
		printTree(child, level+1)
	}
}