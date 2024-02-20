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
	"fmt"
	"net/http"
	"os"

	"reflect"
	"time"

	"github.com/Khan/genqlient/graphql"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/sergi/go-diff/diffmatchpatch"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"k8s.io/apimachinery/pkg/util/rand"
)

var (
	hasSBOMOne model.HasSBOMsHasSBOM
	hasSBOMTwo model.HasSBOMsHasSBOM
)

func CreateGraphFile(pathsOne, pathsTwo [][]*Node, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	file.WriteString("graph G {\n")
	connectNodes(pathsOne, file, " [color=red]")
	connectNodes(pathsTwo, file, " [color=green]")
	file.WriteString("}\n")
	return nil
}

func connectNodes(paths [][]*Node, file *os.File, colorText string) {
	for _, path := range paths {
		if len(path) > 1 {
			for i := 0; i < len(path)-1; i++ {
				if i+1 < len(path) {
					edge := fmt.Sprintf("\t%s -- %s" +colorText+ ";\n", path[i].tag, path[i+1].tag)
					file.WriteString(edge)
				}
			}
		}
	}
}


func findPathsRecursively(node *Node, currentPath []*Node, currentPathString string, allPaths *[][]*Node, allPathsString *[]string) {
	if node == nil {
		return
	}

	currentPath = append(currentPath, node)
	if currentPathString!= "" {
		currentPathString = currentPathString + " -> "
	}
	currentPathString = currentPathString + node.tag

	if node.leaf {
		pathCopy := make([]*Node, len(currentPath))
		copy(pathCopy, currentPath)
		*allPaths = append(*allPaths, pathCopy)
		*allPathsString = append(*allPathsString, currentPathString)
	}

	for _, neighbor := range node.neighbours {
		findPathsRecursively(neighbor, currentPath, currentPathString, allPaths, allPathsString)
	}

	currentPath = currentPath[:len(currentPath)-1]
	
}

func getPaths(head *Node)([][]*Node, []string){
	var allPaths [][]*Node
	var allPathsString []string
	currentPathString := ""
	currentPath := []*Node{}
	findPathsRecursively(head, currentPath, currentPathString, &allPaths, &allPathsString)
	return allPaths, allPathsString
}


func printPaths(paths [][]*Node) {
	count := 0
	for _, path := range paths {
		count += 1
		fmt.Println(getPathString(path)+"\n")
	}
	fmt.Println("Total Paths:", count)
}

func getPathString(path []*Node) string {
	pathStr := ""
	for i, node := range path {
		
		pathStr = pathStr + node.tag
		if (i != (len(path) -1) ) {
			pathStr = pathStr + "->"
		}
	}
	return pathStr
}



func init() {
	rootCmd.AddCommand(diffCmd)
	rootCmd.PersistentFlags().StringSlice("sbom", []string{}, "two sboms to find the diff between")
	rootCmd.PersistentFlags().StringSlice("slsa", []string{}, "two slsa to find the diff between")
	rootCmd.PersistentFlags().Bool("uri", false, "input is a URI")
	rootCmd.PersistentFlags().Bool("purl", false, "input is a pURL")
	rootCmd.PersistentFlags().Bool("test", false, "run in test mode")
	rootCmd.PersistentFlags().Bool("dot", false, "create a dot file to visualize the diff")
	rootCmd.PersistentFlags().String("file", "tests/identical.json", "filename to read sbom test cases from")
}

var diffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Get a unified tree diff for two given SBOMS",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		test, _ := cmd.Flags().GetBool("test")
		testfile, _ := cmd.Flags().GetString("file")
		dot, _ := cmd.Flags().GetBool("dot")

		if !test {
			slsas, _ := cmd.Flags().GetStringSlice("slsa")
			fmt.Println(slsas)
			if len(slsas) > 0 {
				fmt.Println("To be implemented...")
				return
			}
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
		//TODO: @abhi 
		//some sort of sorting should be done here? @abhi
		//Each call to findHasSBOMBy even using the same uri can and does return a struct with arrays that
		//have their elements in random order, when using this to construct the graph the order of the nodes differs
		//so does the returned paths list. When performing the diff, we will need some order to be maintained. 



		//init first node
		nodeOne := Node{Value: hasSBOMOne.Id, tag: "Id"}
		nodeTwo := Node{Value: hasSBOMTwo.Id, tag: "Id"}

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
			// this would be great. Then we can remove the constraint for not including type Subject and Included Software below.
			if  fieldTypeOne != "Id" && fieldTypeOne != "Subject" && fieldTypeOne != "IncludedSoftware" { //not id, subject, included softwares then
				hasSBOMResponsFieldsToGraph(fieldOne, &nodeOne, fieldTypeOne)
			}
			if fieldTypeTwo != "Id" && fieldTypeTwo != "Subject" && fieldTypeTwo != "IncludedSoftware" { //not id, subject, included softwares then
				hasSBOMResponsFieldsToGraph(fieldTwo, &nodeTwo,  fieldTypeTwo)
			}
		}

		//get list of paths in the graph
		pathsOne, pathsOneStrings := getPaths(&nodeOne)
		pathsTwo, pathsTwoStrings := getPaths(&nodeTwo)

		//find the diff
		diffedPathsOne, diffedPathsTwo := getDiff(pathsOne, pathsTwo, pathsOneStrings, pathsTwoStrings, dot)
		if len(diffedPathsOne) == 0 && len(diffedPathsTwo) == 0 {
			fmt.Println("Identical")
			return
		}

		//create the dot files
		if dot{
			if len(diffedPathsOne) == 0 && len(diffedPathsTwo) == 0 {
				fmt.Println("...Skipping graphviz")
				return
			}
			randfilename := rand.String(10)+".dot"
			err := CreateGraphFile(diffedPathsOne, diffedPathsTwo, randfilename ); if err!= nil {
				fmt.Println("Error creating graph file:", err)	
				return
			}else{
				fmt.Println(randfilename)
			}
		}
	},
}


func getPatchMatch(stringOne, stringTwo string, dmp *diffmatchpatch.DiffMatchPatch, enabled bool)  {
	if enabled {
		return
	}
	if stringOne!= "" && stringTwo!= "" {
		fmt.Println(stringOne)
	}
	diffs := dmp.DiffMain(stringOne,stringTwo, false)
	for _, diff := range diffs {
		switch diff.Type {
		case diffmatchpatch.DiffDelete:
			fmt.Printf("(-)%s\n", diff.Text)
		case diffmatchpatch.DiffInsert:
			fmt.Printf("(+)%s\n", diff.Text)
		}
	}
}

func getDiff(pathsOne, pathsTwo [][]*Node, pathsOneStrings, pathsTwoStrings []string, dot bool) ([][]*Node, [][]*Node ){
	var diffOne, diffTwo [][]*Node
	var dmp *diffmatchpatch.DiffMatchPatch
	if !dot {
		dmp = diffmatchpatch.New()
	}

	for i := 0; i < len(pathsOne) || i < len(pathsTwo); i++ {
		if i < len(pathsOne) && i < len(pathsTwo) {
			if pathsOneStrings[i] != pathsTwoStrings[i] {
				diffOne = append(diffOne, pathsOne[i])
				diffTwo = append(diffTwo, pathsTwo[i])
				
				getPatchMatch(pathsOneStrings[i], pathsTwoStrings[i], dmp, dot)
			}
		}else if  i < len(pathsOne) && i >= len(pathsTwo) {
			diffOne = append(diffOne, pathsOne[i])
			getPatchMatch(pathsOneStrings[i], "", dmp, dot)
		}else if i >= len(pathsOne) && i < len(pathsTwo){
			diffTwo = append(diffTwo, pathsTwo[i])
			getPatchMatch("", pathsTwoStrings[i], dmp, dot)
		}
	}
	return diffOne, diffTwo
}


// This function recursively traverses the fields of a struct using reflection and converts them into nodes of a graph. 
// It handles nested structs and arrays within the main struct.
func hasSBOMResponsFieldsToGraph(data reflect.Value, head *Node, heirarchy string) {
	//base case
	if data.Kind() == reflect.String || isPrimitiveType(data.Type()) {
		//just add a neighbour and return
		node := Node{Value: data.Interface(), tag: heirarchy+ ": " + data.String()}
		node.leaf = true
		head.neighbours = append(head.neighbours, &node)
		return
	}

	// edge base case for time.Time to not go into recursion, while being a "struct"
	if data.Kind() == reflect.Struct && data.Type() == reflect.TypeOf(time.Time{}) {
		//just add a neighbour and return
		node := Node{Value: data.Interface(), tag: heirarchy+ ": " + data.Interface().(time.Time).String()}
		node.leaf = true
		head.neighbours = append(head.neighbours, &node)
		return
	}

	node := Node{ tag: data.Type().Name()}
	var newHead *Node

	// if we have a struct, we need to go over its fields
	// update head to be the last element of the neighbours slice

	//this is a check for slices/arrays
	if (node.tag =="" && (data.Kind() == reflect.Slice) || (node.tag =="" && data.Kind() == reflect.Array)) {
		//instead of adding a completely empty node, no value no tag, we are skipping from adding it as a neighbour node, it's fields will 
		//just be neighbours of the parent node
		newHead = head
	}else {
		node.leaf = false
		head.neighbours = append(head.neighbours, &node)
		newHead = head.neighbours[len(head.neighbours)-1]
	}
	
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
		hasSBOMResponsFieldsToGraph(field, newHead, fieldtag)
	}
}