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
	"github.com/guacsec/guac/pkg/assembler/helpers"

)

type Node struct {
	ID string
	Attributes map[string]interface{}
	color string
}

func nodeHash(n *Node) string {
	return n.ID
}

func setNodeAttribute(g graph.Graph[string, *Node],ID, key string, value interface{}){
	var (
		err error
		node *Node
	)
	if node, err = g.Vertex(ID); err !=  nil {
		fmt.Println("Error setting node attribute", err)
		os.Exit(1)
	}

	node.Attributes[key] = value
}

func getPkgResponseFromPurl(ctx context.Context, gqlclient graphql.Client, purl string) (*model.PackagesResponse, error) {
	pkgInput, err := helpers.PurlToPkg(purl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PURL: %v", err)
	}

	pkgQualifierFilter := []model.PackageQualifierSpec{}
	for _, qualifier := range pkgInput.Qualifiers {
		// to prevent https://github.com/golang/go/discussions/56010
		qualifier := qualifier
		pkgQualifierFilter = append(pkgQualifierFilter, model.PackageQualifierSpec{
			Key:   qualifier.Key,
			Value: &qualifier.Value,
		})
	}

	pkgFilter := &model.PkgSpec{
		Type:       &pkgInput.Type,
		Namespace:  pkgInput.Namespace,
		Name:       &pkgInput.Name,
		Version:    pkgInput.Version,
		Subpath:    pkgInput.Subpath,
		Qualifiers: pkgQualifierFilter,
	}
	pkgResponse, err := model.Packages(ctx, gqlclient, *pkgFilter)
	if err != nil {
		return nil, fmt.Errorf("error querying for package: %v", err)
	}
	if len(pkgResponse.Packages) != 1 {
		return nil, fmt.Errorf("failed to located package based on purl")
	}
	return pkgResponse, nil
}

func findHasSBOMBy(uri, purl string, ctx context.Context, gqlclient graphql.Client) (*model.HasSBOMsResponse, error) {
	var foundHasSBOMPkg *model.HasSBOMsResponse
	var err error
	if purl != "" {
		pkgResponse, err := getPkgResponseFromPurl(ctx, gqlclient, purl)
		if err != nil {
			fmt.Printf("getPkgResponseFromPurl - error: %v", err)
			return nil, err
		}
		foundHasSBOMPkg, err = model.HasSBOMs(ctx, gqlclient, model.HasSBOMSpec{Subject: &model.PackageOrArtifactSpec{Package: &model.PkgSpec{Id: &pkgResponse.Packages[0].Namespaces[0].Names[0].Versions[0].Id}},
			})
		if err != nil {
			fmt.Printf("failed getting hasSBOM with error :%v", err)
			return nil, err
		}
	} else {
		foundHasSBOMPkg, err = model.HasSBOMs(ctx, gqlclient, model.HasSBOMSpec{Uri: &uri,})
		if err != nil {
			fmt.Printf("failed getting hasSBOM  with error: %v", err)
			return nil, err
		}
	}
	return foundHasSBOMPkg, nil
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

func createGraphDotFile(g graph.Graph[string, *Node]){
	filename := rand.String(10)+".dot"
	file, _ := os.Create(filename)
	err := draw.DOT(g, file)
	if err!= nil {
		fmt.Println("Error creating dot file:", err)
		os.Exit(1)
	}
	fmt.Println(filename)
}

func highlightDiff(gOne, gTwo graph.Graph[string, *Node]) graph.Graph[string, *Node] {
	//create diff graph
	var g, overlay graph.Graph[string, *Node]
	var overlayNodes map[string]map[string]graph.Edge[string]
	gOneNodes,err := gOne.AdjacencyMap()
	if err != nil {
		fmt.Println("Unable to get overlay AdjacencyMap:", err)
		os.Exit(1)
	}
	gTwoNodes, err := gTwo.AdjacencyMap()
	if err != nil {
		fmt.Println("Unable to get base AdjacencyMap:", err)
		os.Exit(1)
	}

	if len(gOneNodes) < len(gTwoNodes){
		g, err = gOne.Clone()
		overlay = gTwo
		overlayNodes = gTwoNodes
	}else if len(gOneNodes) > len(gTwoNodes) {
		g, err = gTwo.Clone()
		overlay = gOne
		overlayNodes = gOneNodes
	}else{
		g, err = gOne.Clone()
		overlay = gTwo
		overlayNodes = gTwoNodes
	}

	if err != nil {
		fmt.Println("Unable to clone graph:", err)
		os.Exit(1)
	}
	
	//check nodes and their data
	for overlayNodeID, _ := range(overlayNodes){
		if _, err = g.Vertex(overlayNodeID); err == nil {
			nodeOverlay, _ := overlay.Vertex(overlayNodeID)
			nodeG, _ := g.Vertex(overlayNodeID)
			//TODO: if nodes are not equal we need to highlight which attribute is different 
			if (len(nodeOverlay.Attributes) != len(nodeG.Attributes)){
				//what to do here?
				break
			} 
			for key, _ := range nodeOverlay.Attributes {
				if (nodeOverlay.Attributes[key] != nodeG.Attributes[key]) {
					//instead of adding a node, just change the color, do we need to display the differences?
					break
				}
			}
		}else {
			addGraphNode(g, overlayNodeID, "red") //change color to red
		}
	}	

	//add edges not in diff but from g2
	edges, err := overlay.Edges()
	if err != nil {
		fmt.Println("Error getting edges:", err)
		os.Exit(1)
	}

	for _, edge := range edges {
		_, err := g.Edge(edge.Source, edge.Target)
		if err != nil { //missing edge, add with red color
			addGraphEdge(g, edge.Source, edge.Target, "red") //hmm how to add color?
		}
	}
	return g
}

func makeGraph(hasSBOM model.HasSBOMsHasSBOM) graph.Graph[string, *Node] {

	g := graph.New(nodeHash, graph.Directed())

	//create HasSBOM node
	hasSBOMNode := &Node{ID: "HasSBOM", color: "black", Attributes: make(map[string]interface{}) }
	g.AddVertex(hasSBOMNode, graph.VertexAttribute("color", "black"))
	//add metadata
	setNodeAttribute(g, hasSBOMNode.ID, "Id" , hasSBOM.Id)
	setNodeAttribute(g, hasSBOMNode.ID, "Algorithm" , hasSBOM.Algorithm)
	setNodeAttribute(g, hasSBOMNode.ID, "Collector" , hasSBOM.Collector)
	setNodeAttribute(g, hasSBOMNode.ID, "Digest" , hasSBOM.Digest)
	setNodeAttribute(g, hasSBOMNode.ID, "DownloadLocation" , hasSBOM.DownloadLocation)
	setNodeAttribute(g, hasSBOMNode.ID, "KnownSince" , hasSBOM.KnownSince.String())
	setNodeAttribute(g, hasSBOMNode.ID, "Origin" , hasSBOM.Origin)
	setNodeAttribute(g, hasSBOMNode.ID, "Uri" , hasSBOM.Uri)
	//TODO: add subject

	//add included occurrences
	for _, occurrence := range hasSBOM.IncludedOccurrences {
		setNodeAttribute(g, hasSBOMNode.ID, "InclOccur-"+ occurrence.Id + "-Subject", occurrence.Subject)
		setNodeAttribute(g, hasSBOMNode.ID, "InclOccur-"+ occurrence.Id + "-Artifact-Id", occurrence.Artifact.Id)
		setNodeAttribute(g, hasSBOMNode.ID, "InclOccur-"+ occurrence.Id + "-Artifact-Algorithm", occurrence.Artifact.Algorithm)
		setNodeAttribute(g, hasSBOMNode.ID, "InclOccur-"+ occurrence.Id + "-Artifact-Digest", occurrence.Artifact.Digest)
		setNodeAttribute(g, hasSBOMNode.ID, "InclOccur-"+ occurrence.Id + "-Justification", occurrence.Justification)
		setNodeAttribute(g, hasSBOMNode.ID, "InclOccur-"+ occurrence.Id + "-Origin", occurrence.Origin)
		setNodeAttribute(g, hasSBOMNode.ID, "InclOccur-"+ occurrence.Id + "-Collector", occurrence.Collector)
	}	

	//TODO: add included software

	//add included dependencies
	for _, dependency := range hasSBOM.IncludedDependencies {
		packageId := dependency.Package.Id
		addGraphEdge(g, hasSBOMNode.ID ,packageId,"black")
		includedDepsId := dependency.Id
		addGraphEdge(g, packageId, includedDepsId, "black")

		setNodeAttribute(g,  packageId, "Type" , dependency.Package.Type)
		//TODO:add namespaces
		setNodeAttribute(g,  includedDepsId, "Justification" , dependency.Justification)

		if dependency.DependencyPackage.Id != "" {
			dependPkgId := dependency.DependencyPackage.Id
			addGraphEdge(g, includedDepsId, dependPkgId, "black")
			setNodeAttribute(g,  dependPkgId, "Type" , dependency.DependencyPackage.Type)
			setNodeAttribute(g,  dependPkgId, "DependencyType" , dependency.DependencyPackage.Type)
			setNodeAttribute(g,  dependPkgId, "VersionRange" , dependency.DependencyPackage.Type)
			setNodeAttribute(g,  dependPkgId, "Origin" , dependency.DependencyPackage.Type)
			setNodeAttribute(g,  dependPkgId, "Collector" , dependency.DependencyPackage.Type)
			//TODO:add namespaces
		}
	}
	return g
}

func addGraphNode(g graph.Graph[string, *Node],_ID, color string){
	var err error
	if _, err = g.Vertex(_ID); err ==  nil {
		return
	}

	newNode := &Node{
		ID: _ID,
		color: "black", 
		Attributes: make(map[string]interface{}),
	}

	err = g.AddVertex(newNode, graph.VertexAttribute("color", color))
	if err != nil {
		fmt.Println("Node existing after check:", err)
	}
}

func addGraphEdge(g graph.Graph[string, *Node], from, to, color string){
	addGraphNode(g, from, "black")
	addGraphNode(g, to, "black")

	_, err  := g.Edge(from, to)
	if err == nil {
		return
	}
	g.AddEdge(from, to, graph.EdgeAttribute("color", color)) 
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
