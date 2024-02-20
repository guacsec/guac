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

	// "time"

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

var (
	hasSBOMOne model.HasSBOMsHasSBOM
	hasSBOMTwo model.HasSBOMsHasSBOM
)


type DiffNode struct {
	tag         string
	OldValue    interface{}
	NewValue    interface{}
	leafChanged bool
}

// DFSNodeDiff performs a DFS diff between two nodes
func DFSNodeDiff(oldNode, newNode *Node) []DiffNode {
	var diffs []DiffNode
	dfsNodeDiff(oldNode, newNode, &diffs)
	return diffs
}

// dfsNodeDiff performs the DFS traversal and comparison
func dfsNodeDiff(oldNode, newNode *Node, diffs *[]DiffNode) {
	// Check if both nodes are nil
	if oldNode == nil && newNode == nil {
		return
	}

	// Check if one of the nodes is nil
	if oldNode == nil || newNode == nil {
		var tag string
		if newNode != nil{
			tag= newNode.tag
		} 

		if oldNode != nil{
			tag= oldNode.tag
		}
		*diffs = append(*diffs, DiffNode{tag: tag, OldValue: oldNode, NewValue: newNode, leafChanged: true})
		return
	}

	// Check if leaf nodes have different values
	if oldNode.leaf && newNode.leaf && oldNode.Value != newNode.Value {
		*diffs = append(*diffs, DiffNode{tag: oldNode.tag, OldValue: oldNode.Value, NewValue: newNode.Value, leafChanged: true})
		return
	}

	// Recursively process neighbours
	for i := 0; i  < len(oldNode.neighbours) || i < len(newNode.neighbours); i++ {
		var oldNeighbor, newNeighbor *Node

		if i < len(oldNode.neighbours) {
			oldNeighbor = oldNode.neighbours[i]
		}
		if i < len(newNode.neighbours) {
			newNeighbor = newNode.neighbours[i]
		}
		dfsNodeDiff(oldNeighbor, newNeighbor, diffs)
	}
}

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
			hasSBOMOne =  hasSBOMResponseOne.HasSBOM[0]
			hasSBOMTwo =  hasSBOMResponseTwo.HasSBOM[0]

		}else{
			jsonData, err := os.ReadFile(testfile)
			if err != nil {
				fmt.Println("Error reading test:", err)
				return
			}

			var test SBOMDiffTest
			err = json.Unmarshal(jsonData, &test)
			if err != nil {
				fmt.Println("Error:", err)
				return
			}
			hasSBOMOne = test.HasSBOMOne
			hasSBOMTwo = test.HasSBOMTwo
		}
		//init first node
		nodeOne := Node{Value: hasSBOMOne.Id, tag: "id"}
		nodeTwo := Node{Value: hasSBOMTwo.Id, tag: "id"}

		// offset to field(0) to come to get to AllHasSBOMTree
		allHasSBOMTreeOne := reflect.ValueOf(hasSBOMOne).Field(0)
		allHasSBOMTreeTwo := reflect.ValueOf(hasSBOMTwo).Field(0)

		//AllHasSBOMTree is a struct
		//convert the HasSBOM to a graph, 
		for i := 0; i < allHasSBOMTreeOne.NumField(); i++ {
			fieldOne := allHasSBOMTreeOne.Field(i)
			fieldTwo := allHasSBOMTreeTwo.Field(i)
			fieldTypeOne := reflect.TypeOf(allHasSBOMTreeOne.Interface()).Field(i).Name 
			fieldTypeTwo := reflect.TypeOf(allHasSBOMTreeTwo.Interface()).Field(i).Name 
			//TODO  @abhi If you could take a look at taking care of cases where the field type is []json.RawMessage, interface or pointers 
			// this would be great.
			if  fieldTypeOne != "Id" || fieldTypeOne != "Subject" || fieldTypeOne != "IncludedSoftware" { //not id, subject, included softwares then
				hasSBOMResponsFieldsToGraph(fieldOne, &nodeOne,  allHasSBOMTreeTwo.Type().Name() + "|" + fieldTypeOne)
			}
			if fieldTypeTwo != "Id" || fieldTypeTwo != "Subject" || fieldTypeTwo != "IncludedSoftware" { //not id, subject, included softwares then
				hasSBOMResponsFieldsToGraph(fieldTwo, &nodeTwo, allHasSBOMTreeTwo.Type().Name() +  "|" + fieldTypeTwo)
			}
		}

		//get list of paths in the graph
		// pathsOne := getPaths(&nodeOne)
		// pathsTwo := getPaths(&nodeTwo)





		



	},
}

// func getPaths(head *Node) [][]*Node {


// }

// This function recursively traverses the fields of a struct using reflection and converts them into nodes of a graph. 
// It handles nested structs and arrays within the main struct.
func hasSBOMResponsFieldsToGraph(data reflect.Value, head *Node, heirarchy string) {
	//base case
	if data.Kind() == reflect.String {
		//just add a neighbour and return
		node := Node{Value: data.Interface(), tag: heirarchy}
		node.leaf = true
		head.neighbours = append(head.neighbours, &node)
		return
	}

	// edge base case for time.Time to not go into recursion, while being a "struct"
	if data.Kind() == reflect.Struct && data.Type() == reflect.TypeOf(time.Time{}) {
		node := Node{Value: data.Interface(), tag: heirarchy}
		node.leaf = true
		head.neighbours = append(head.neighbours, &node)
		return
	}
	newHeirarchy :=  heirarchy + "|"+data.Type().Name()
	node := Node{tag: newHeirarchy}
	node.leaf = false
	head.neighbours = append(head.neighbours, &node)
	//TODO: arorasoham9 this does not consider field type of interfaces or pointers or []json.rawmessage. I still need to work on that

	
	// if we have a struct, we need to go over its fields
	// update head to be the last element of the neighbours slice
	newHead := head.neighbours[len(head.neighbours)-1]
	var length = 0
	var field reflect.Value

	if data.Kind() == reflect.Struct {
		length = data.NumField()
	}else if data.Kind() == reflect.Array || data.Kind() == reflect.Slice {
		length = data.Len()
	}
	fieldtag := ""
	for i := 0; i < length; i++ {
		if data.Kind() == reflect.Struct {
			field = data.Field(i)
			structtype := reflect.TypeOf(data.Interface())
			fieldtag = structtype.Field(i).Name
		}else if data.Kind() == reflect.Array || data.Kind() == reflect.Slice {
			field = data.Index(i)
			fieldtag = data.Type().Name()
		}
		hasSBOMResponsFieldsToGraph(field, newHead, newHeirarchy + "|"+fieldtag)
	}
}

