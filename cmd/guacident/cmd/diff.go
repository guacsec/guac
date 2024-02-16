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
	"encoding/json"
	"time"

	"fmt"
	"net/http"
	"os"
	"reflect"
	"github.com/sergi/go-diff/diffmatchpatch"
	"github.com/Khan/genqlient/graphql"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	
)

var (
	hasSBOMOne []model.HasSBOMsHasSBOM
	hasSBOMTwo []model.HasSBOMsHasSBOM
)

func init() {
	rootCmd.AddCommand(diffCmd)
	rootCmd.PersistentFlags().StringSlice("boms", []string{}, "two sboms to find the diff between")
	rootCmd.PersistentFlags().Bool("uri", false, "input is a URI")
	rootCmd.PersistentFlags().Bool("purl", false, "input is a pURL")
	rootCmd.PersistentFlags().Bool("test", false, "run in test mode")
	rootCmd.PersistentFlags().String("file", "tests/identical.json", "filename to read sbom test cases from")
}

var diffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Get a unified tree diff for two given SBOMS",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		test, _ := cmd.Flags().GetBool("test")
		testfile, _ := cmd.Flags().GetString("file")

		if !test {
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
			hasSBOMOne = append( hasSBOMOne,hasSBOMResponseOne.HasSBOM[0])
			hasSBOMTwo = append( hasSBOMTwo,hasSBOMResponseTwo.HasSBOM[0])

		}else{
			jsonData, err := os.ReadFile(testfile)
			if err != nil {
				fmt.Println("Error reading test:", err)
				return
			}

			var test []SBOMDiffTest
			err = json.Unmarshal(jsonData, &test)
			if err != nil {
				fmt.Println("Error:", err)
				return
			}
			for _, t := range test {
				hasSBOMOne = append( hasSBOMOne,t.HasSBOMOne)
				hasSBOMTwo = append( hasSBOMTwo,t.HasSBOMTwo)
			}
		}
		nodeOne := Node{Value: hasSBOMOne}
		nodeTwo := Node{Value: hasSBOMTwo}

		hasSBOMResponseToGraph(reflect.ValueOf(hasSBOMOne), &nodeOne)
		hasSBOMResponseToGraph(reflect.ValueOf(hasSBOMTwo), &nodeTwo)

		// //offset to the first node, ignoring the node for the whole struct built twice in the graph
		nodeOne = *nodeOne.neighbours[0].neighbours[0].neighbours[0]
		nodeTwo = *nodeTwo.neighbours[0].neighbours[0].neighbours[0]

		// //flatten the graph
		nodeOneString := FlattenGraphToString(&nodeOne, nodeOne.tag) 
		nodeTwoString := FlattenGraphToString(&nodeTwo, nodeTwo.tag) 

		//perform a diff on the flat graph
		findFraserDiff(nodeOneString, nodeTwoString)
	},
}
// The github.com/sergi/go-diff/diffmatchpatch package is a Go implementation of Neil Fraser's Diff Match Patch library,
// which provides robust algorithms to perform diff, match, and patch operations on plain text.
func findFraserDiff(flatGraphOne, flatGraphTwo string){
	dmp := diffmatchpatch.New()

	// Compute the differences between the two strings
	diffs := dmp.DiffMain(flatGraphOne,flatGraphTwo, true)
	identical := true
	for _, diff := range diffs {
		switch diff.Type {
		case diffmatchpatch.DiffDelete:
			identical = false
			fmt.Printf("Deleted: %s\n", diff.Text)
		case diffmatchpatch.DiffInsert:
			identical = false
			fmt.Printf("Inserted: %s\n", diff.Text)
		case diffmatchpatch.DiffEqual:
			//do nothing
		}
	}

	if identical {
		fmt.Println("SBOMs are identical")
	}

}

func FlattenGraphToString(node *Node, parentTag string) string {
    var result string
	
	if node == nil || node.Value == nil {
		//ideally nothing should be nil, but since we are ignoring the subject, and a few more fields in HasSBOMsHasSBOM type,
		//some fields may be nil for now
		return ""
	}
	
    if node.leaf || parentTag == "Time" {
        return fmt.Sprintf("\t(%v)\n", node.Value)
    }
	
    // Add the tag of the current node to the result string
    result += "\n"+node.tag + ":"

    // If the value of the node is a struct, slice or array add a newline and indent the next level
    if reflect.TypeOf(node.Value).Kind() == reflect.Struct || reflect.TypeOf(node.Value).Kind() == reflect.Slice || reflect.TypeOf(node.Value).Kind() == reflect.Array  {
        result += "\n"
    }

    // Add the value of the current node to the result string
	if isPrimitiveType(reflect.TypeOf(node.Value)) {
		result += fmt.Sprintf("\t%v\n", node.Value)
	}

    //  recursively flatten neighbours of the current node
    for _, neighbor := range node.neighbours {
        result += FlattenGraphToString(neighbor, node.tag)
    }

    return result
}
// This function recursively traverses the fields of a struct using reflection and converts them into nodes of a graph. 
// It handles nested structs and arrays within the main struct.
func hasSBOMResponseToGraph(data reflect.Value, head *Node) {

	node := Node{Value: data.Interface(), tag: data.Type().Name()}
	head.neighbours = append(head.neighbours, &node)

	//base case
	if data.Kind() == reflect.String {
	// if data.Kind() != reflect.Array && data.Kind() != reflect.Slice && data.Kind() != reflect.Struct {
		//just add a neighbour and return
		node.leaf = true
		return
	}
	// edge base case for time.Time to not go into recursion, while being a "struct"
	if data.Kind() == reflect.Struct && data.Type() == reflect.TypeOf(time.Time{}) {
		node.tag = "Time"
		node.leaf = true
		return
	}
	node.leaf = false

	//TODO: arorasoham9 this does not consider field type of interfaces or pointers or []json.rawmessage. I still need to work on that

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
		node.printValue = false
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

