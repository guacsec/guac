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

	"github.com/Khan/genqlient/graphql"
	"github.com/dominikbraun/graph"
	"github.com/dominikbraun/graph/draw"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"k8s.io/apimachinery/pkg/util/rand"
)


type Node struct {
	ID string
	Attributes map[string]interface{}
	color string
}
type Graph struct {
    graph graph.Graph[string, string]        
    Attributes map[string]interface{}
	Nodes map[string]*Node
}

func (g *Graph) AddGraphNode(node *Node) {
	g.Nodes[node.ID] = node
	g.Nodes[node.ID].Attributes = make(map[string]interface{})

	g.graph.AddVertex(node.ID)

	// if err != nil { //check if the err is "node Exists error"
	// 	fmt.Println("Error adding graph vertex:", err)
	// 	os.Exit(1)
	// }
}

func (g *Graph) NodeExists(ID string) bool {
	_, ok := g.Nodes[ID]
	return ok
}

func (g *Graph) AddGraphEdge(to, from string) {
	//check if both edges exist first
	if !g.NodeExists(to) {
		// fmt.Println("from here1")
		g.AddGraphNode(&Node{ID: to, color: "black"})
	}

	if !g.NodeExists(from) {
		// fmt.Println("from here2")
		g.AddGraphNode(&Node{ID: from, color: "black"})
	}

    err := g.graph.AddEdge(to, from)
	if err != nil { 
		fmt.Println("Error adding graph edge:", err)
		os.Exit(1)
	}

}

func (g *Graph) SetAttribute(key string, value interface{}) {
    g.Attributes[key] = value
}

func NewGraph() *Graph {
    return &Graph{
        graph:      graph.New(graph.StringHash, graph.Directed()),
        Attributes: make(map[string]interface{}),
		Nodes: make(map[string]*Node),
    }
}

func (g *Graph) SetNodeAttribute(id, key string, value interface{}){
	g.Nodes[id].Attributes[key] = value
}

func init() {
	rootCmd.AddCommand(diffCmd)
	rootCmd.PersistentFlags().StringSlice("sboms", []string{}, "two sboms to find the diff between")
	rootCmd.PersistentFlags().StringSlice("slsa", []string{}, "two slsa to find the diff between")
	rootCmd.PersistentFlags().Bool("uri", false, "input is a URI")
	rootCmd.PersistentFlags().Bool("purl", false, "input is a pURL")
	rootCmd.PersistentFlags().Bool("test", false, "run in test mode")
	rootCmd.PersistentFlags().String("file", "tests/identical.json", "filename to read sbom test cases from")
}

func verifyFlags(slsas, sboms []string,  errSlsa, errSbom error, uri, purl bool) {
	if (errSlsa != nil && errSbom != nil) || (len(slsas) ==0  && len(sboms) == 0 ){
		fmt.Println("Must specify slsa or sboms")
		os.Exit(0)
	}

	if len(slsas) >0  && len(sboms) >0 {
		fmt.Println("Must either specify slsa or sbom")
		os.Exit(0)
	}

	if errSlsa == nil && (len(slsas) <= 1|| len(slsas) > 2) && len(sboms) == 0{
		fmt.Println("Must specify exactly two slsas to find the diff between, specified", len(slsas))
		os.Exit(0)
	}

	if errSbom == nil && (len(sboms) <= 1|| len(sboms) > 2) && len(slsas) == 0{
		fmt.Println("Must specify exactly two sboms to find the diff between, specified", len(sboms))
		os.Exit(0)
	}

	if errSlsa == nil && len(slsas) == 2 {
		fmt.Println("slsa diff to be implemented.")
		os.Exit(0)
	}

	if !uri && !purl {
		fmt.Println("Must provide one of --uri or --purl")
		os.Exit(0)
	}

	if uri && purl {
		fmt.Println("Must provide only one of --uri or --purl")
		os.Exit(0)
	}
}

var diffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Get a unified tree diff for two given SBOMS",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		test, _ := cmd.Flags().GetBool("test")
		testfile, _ := cmd.Flags().GetString("file")
		var err error
		var (
			hasSBOMOne model.HasSBOMsHasSBOM
			hasSBOMTwo model.HasSBOMsHasSBOM
		)

		if !test {
			slsas, errSlsa := cmd.Flags().GetStringSlice("slsa")
			sboms, errSbom := cmd.Flags().GetStringSlice("sboms")
			uri, _ := cmd.Flags().GetBool("uri")
			purl, _ := cmd.Flags().GetBool("purl")
			verifyFlags(slsas, sboms,  errSlsa, errSbom, uri, purl)

			ctx := logging.WithLogger(context.Background())
			httpClient := http.Client{}
			gqlclient := graphql.NewClient(viper.GetString("gql-addr"), &httpClient)
			var hasSBOMResponseOne *model.HasSBOMsResponse
			var hasSBOMResponseTwo *model.HasSBOMsResponse

			if uri {
				hasSBOMResponseOne, err = findHasSBOMBy(sboms[0],"",  ctx, gqlclient)
				if err != nil {
					fmt.Println("failed to lookup sbom: %s %v", sboms[0], err)
					return
				}

				hasSBOMResponseTwo, err = findHasSBOMBy( sboms[1],"",  ctx, gqlclient)
				if err != nil {
					fmt.Println("failed to lookup sbom: %s %v", sboms[1], err)
					return
				}
			} else if purl {

				hasSBOMResponseTwo, err = findHasSBOMBy( "", sboms[0],  ctx, gqlclient)
				if err != nil {
					fmt.Println("failed to lookup sbom: %s %v", sboms[0], err)
					return
				}
				hasSBOMResponseTwo, err = findHasSBOMBy( "", sboms[1], ctx, gqlclient)
				if err != nil {
					fmt.Println("failed to lookup sbom: %s %v", sboms[1], err)
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
		//create graphs
		gOne := makeGraph(hasSBOMOne)
		gTwo := makeGraph(hasSBOMTwo)

		//diff
		diffGraph := highlightDiff(gOne, gTwo)

		//create the dot file
		createGraphDotFile(diffGraph)
	},
}

func createGraphDotFile(g *Graph){
	filename := rand.String(10)+".dot"
	file, _ := os.Create(filename)
	err := draw.DOT(g.graph, file)
	if err!= nil {
		fmt.Println("Error creating dot file:", err)
		os.Exit(1)
	}
	fmt.Println(filename)
}

func graphCopy(g *Graph) *Graph {
	gclone := NewGraph()


	graphCopy, err := g.graph.Clone()
	if err!= nil {
		fmt.Println("Error copying graph:", err)
		os.Exit(1)
	}
	gclone.graph = graphCopy


	//copy nodes
	for _, node := range(g.Nodes){
		if node, ok := g.Nodes[node.ID]; ok {
			g.AddGraphNode(node)
		}
	}

	return gclone
}

func highlightDiff(base, overlay *Graph) *Graph {
	//create diff graph
	g := graphCopy(base)

	//check nodes and their data
	for _, node := range(overlay.Nodes){
		if _, ok := g.Nodes[node.ID]; ok {
			for key, _ := range node.Attributes {
				if (overlay.Nodes[node.ID].Attributes[key] != g.Nodes[node.ID].Attributes[key]) {
					g.AddGraphNode(&Node{ //
						ID: node.ID,
						Attributes: node.Attributes,
						color: "yellow", //change color to yellow
					}) 
				}
		}
		}else {

			g.AddGraphNode(&Node{
				ID: node.ID,
				Attributes: node.Attributes,
				color: "red",
			}) //change color to red
		}
	}	

	//add edges not in diff but from g2
	edges, err := overlay.graph.Edges()
	if err != nil {
		fmt.Println("Error getting edges:", err)
		os.Exit(1)
	}

	for _, edge := range edges {
		_, err := g.graph.Edge(edge.Source, edge.Target)
		if err != nil { //missing edge, add with red color
			g.AddGraphEdge(edge.Source, edge.Target) //hmm how to add color?
		}
	}
	return g
}

func makeGraph(hasSBOM model.HasSBOMsHasSBOM) *Graph {

	g := NewGraph()
	g.SetAttribute("Id", hasSBOM.Id)
	g.SetAttribute("Uri", hasSBOM.Uri)
	g.SetAttribute("Algorithm", hasSBOM.Algorithm)
	g.SetAttribute("Digest", hasSBOM.Digest)
	g.SetAttribute("DownloadLocation", hasSBOM.DownloadLocation)
	g.SetAttribute("Origin", hasSBOM.Origin)
	g.SetAttribute("Collector", hasSBOM.Collector)
	g.SetAttribute("KnownSince", hasSBOM.KnownSince.String())
	g.SetAttribute("Subject", hasSBOM.Subject)
	for _, dependency := range hasSBOM.IncludedDependencies {
		packageId := dependency.Package.Id
		includedDepsId := dependency.Id
		g.AddGraphEdge(packageId, includedDepsId)
		if dependency.DependencyPackage.Id != "" {
			dependPkgId := dependency.DependencyPackage.Id
			g.AddGraphEdge(includedDepsId, dependPkgId)
			g.SetNodeAttribute(dependPkgId, "namespaces" , dependency.DependencyPackage.Namespaces )//change from abhi's implementation
		}
		g.SetNodeAttribute(packageId, "namespaces" , dependency.Package.Namespaces  ) //change from abhi's implementation
		g.SetNodeAttribute(includedDepsId, "version" , dependency.VersionRange) //change from abhi's implementation
	}
	return g
}



