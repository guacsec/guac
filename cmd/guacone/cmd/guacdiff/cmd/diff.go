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

	"github.com/Khan/genqlient/graphql"
	"github.com/dominikbraun/graph"
	"github.com/dominikbraun/graph/draw"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"k8s.io/apimachinery/pkg/util/rand"
)

const PRINT_MAX = 20

type HighlightedDiff struct {
	MissingLinks [][]string
	MissingNodes []string
	MetadataMismatch []string
}

type Node struct {
	ID string
	Attributes map[string]interface{}
	color string
}

func nodeHash(n *Node) string {
	return n.ID
}

func truncate(original string, length int) string {
    if len(original) > 20 {
        return original[:length]
    } else {
        return original
    }
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

func findHasSBOMBy(filter model.HasSBOMSpec, uri, purl string, ctx context.Context, gqlclient graphql.Client) (*model.HasSBOMsResponse, error) {
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
			fmt.Printf("(purl)failed getting hasSBOM with error :%v", err)
			return nil, err
		}
	} else if uri != ""{
		foundHasSBOMPkg, err = model.HasSBOMs(ctx, gqlclient, model.HasSBOMSpec{Uri: &uri,})
		if err != nil {
			fmt.Printf("(uri)failed getting hasSBOM  with error: %v", err)
			return nil, err
		}
	}else {
		foundHasSBOMPkg, err = model.HasSBOMs(ctx, gqlclient, filter)
		if err != nil {
			fmt.Printf("(filter)failed getting hasSBOM  with error: %v", err)
			return nil, err
		}
	}
	return foundHasSBOMPkg, nil
}

func verifyDiffFlags(slsas, sboms []string,  errSlsa, errSbom error, uri, purl bool) {
	if rootCmd.PersistentFlags().Changed("ID"){
		fmt.Println("ID cannot be specified without --list")
		os.Exit(0)
	}

	if rootCmd.PersistentFlags().Changed("Algorithm"){
		fmt.Println("Algorithm cannot be specified without --list")
		os.Exit(0)
	}

	if rootCmd.PersistentFlags().Changed("Digest"){
		fmt.Println("Digest cannot be specified without --list")
		os.Exit(0)
	}

	if rootCmd.PersistentFlags().Changed("Downloc"){
		fmt.Println("Downloc cannot be specified without --list")
		os.Exit(0)
	}

	if rootCmd.PersistentFlags().Changed("Origin"){
		fmt.Println("Origin cannot be specified without --list")
		os.Exit(0)
	}

	if rootCmd.PersistentFlags().Changed("URI"){
		fmt.Println("URI cannot be specified without --list")
		os.Exit(0)
	}

	if rootCmd.PersistentFlags().Changed("Collector"){
		fmt.Println("Collector cannot be specified without --list")
		os.Exit(0)
	}

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

func printSBOMs(sboms []model.HasSBOMsHasSBOM, all bool, maxprint int) {

	table := tablewriter.NewWriter(os.Stdout)

	table.SetHeader([]string{"ID", "Uri", "Algorithm", "Digest", "Download Location", "Origin", "Collector", "known Since"})

	for i, sbom := range sboms {
		if (!all && i+1 == maxprint){
			break
		}
		table.Append([]string{truncate(sbom.Id,20), truncate(sbom.Uri,20), truncate(sbom.Algorithm,20), truncate(sbom.Digest,20), truncate(sbom.DownloadLocation,20), truncate(sbom.Origin,20), truncate(sbom.Collector,20), truncate(sbom.KnownSince.String(),20)})
	}

	table.SetAlignment(tablewriter.ALIGN_LEFT)

	table.Render()
	if (!all && len(sboms) > maxprint){
		fmt.Println("Run with --all to see all sboms")
	}
}

var diffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Get a unified tree diff for two given SBOMS",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		ctx := logging.WithLogger(context.Background())
		httpClient := http.Client{}
		gqlclient := graphql.NewClient(viper.GetString("gql-addr"), &httpClient)

		showDiffList( cmd, ctx , gqlclient)

		//create graphs
		graphs := hasSBOMToGraph(cmd, ctx, gqlclient)

		//diff
		diffGraph, diffList := highlightDiff(graphs[0], graphs[1])


		
		dot, _ := cmd.Flags().GetBool("dot")
		if dot {
			//create the dot file
			createGraphDotFile(diffGraph)
		} else {
			//print to stdout
			all, _ := cmd.Flags().GetBool("all")
			maxprint, _ := cmd.Flags().GetInt("maxprint")
			printHighlightedDiff(diffList, all, maxprint)
		}
	},
}
func max(nums []int) int {
	if len(nums) == 0 {
		panic("max: no numbers provided")
	}
	max := nums[0]
	for _, num := range nums[1:] {
		if num > max {
			max = num
		}
	}
	return max
}
func printHighlightedDiff(diffList HighlightedDiff, all bool, maxprint int){

	table := tablewriter.NewWriter(os.Stdout)

	table.SetHeader([]string{"Missing Nodes", "Missing Links", "Metadata mismatch"})
	max := max([]int{len(diffList.MissingNodes), len(diffList.MissingLinks), len(diffList.MetadataMismatch)})
	
	for  i:=0 ; i < max;i++ {
		var appendList	[]string
		if (!all && i+1 == maxprint){
			break
		}
		if (i < len(diffList.MissingNodes)){
			appendList = append(appendList, diffList.MissingNodes[i])
		}else {
			appendList = append(appendList, "")
		}
		if (i < len(diffList.MissingLinks)){
			appendList = append(appendList, diffList.MissingLinks[i][0] + "---"+ diffList.MissingLinks[i][1] )
		}else{
			appendList = append(appendList, "")
		}

		if (i < len(diffList.MetadataMismatch)){
			appendList = append(appendList, diffList.MetadataMismatch[i])
		}else{
			appendList = append(appendList, "")
		}
		
		table.Append(appendList)
	}

	table.SetAlignment(tablewriter.ALIGN_LEFT)

	table.Render()
	if (!all && max > maxprint){
		fmt.Println("Run with --all to see all sboms")
	}

}

func verifyDiffListExtraFlags(){
	if rootCmd.PersistentFlags().Changed("slsa") {
		fmt.Println("Cannot specify --slsa with --list")
		os.Exit(0)
	}

	if rootCmd.PersistentFlags().Changed("sboms") {
		fmt.Println("Cannot specify --sboms with --list")
		os.Exit(0)
	}

	if rootCmd.PersistentFlags().Changed("uri") {
		fmt.Println("Cannot specify --uri with --list")
		os.Exit(0)
	}

	if rootCmd.PersistentFlags().Changed("purl") {
		fmt.Println("Cannot specify --purl with --list")
		os.Exit(0)
	}

	if rootCmd.PersistentFlags().Changed("metadata") {
		fmt.Println("Cannot specify --metadata with --list")
		os.Exit(0)
	}
	if rootCmd.PersistentFlags().Changed("inclSoft") {
		fmt.Println("Cannot specify --inclSoft with --list")
		os.Exit(0)
	}

	if rootCmd.PersistentFlags().Changed("inclDeps") {
		fmt.Println("Cannot specify --inclDeps with --list")
		os.Exit(0)
	}
	if rootCmd.PersistentFlags().Changed("inclOccur") {
		fmt.Println("Cannot specify --inclOccur with --list")
		os.Exit(0)
	}
	if rootCmd.PersistentFlags().Changed("namespaces") {
		fmt.Println("Cannot specify --namespaces with --list")
		os.Exit(0)
	}

}

func showDiffList(cmd *cobra.Command, ctx context.Context, gqlclient graphql.Client){

	list, _ := rootCmd.PersistentFlags().GetBool("list")
	if !list {
		return
	}
	verifyDiffListExtraFlags()
	var (
		listIdAddr *string
		listUriAddr *string
		listAlgorithmAddr *string
		listCollectorAddr *string
		listOriginAddr *string
		listDigestAddr *string
		listDownloadLocationAddr *string
	)
	
	if rootCmd.PersistentFlags().Changed("ID"){
		listID, _ := cmd.Flags().GetString("ID")
		listIdAddr = &listID
	}

	if rootCmd.PersistentFlags().Changed("Algorithm"){
		listAlgorithm, _ := cmd.Flags().GetString("Algorithm")
		listAlgorithmAddr = &listAlgorithm
	}

	if rootCmd.PersistentFlags().Changed("Digest"){
		listDigest, _ := cmd.Flags().GetString("Digest")
		listDigestAddr = &listDigest	
	}

	if rootCmd.PersistentFlags().Changed("Downloc"){
		listDownloc, _ := cmd.Flags().GetString("Downloc")
		listDownloadLocationAddr = &listDownloc
	}

	if rootCmd.PersistentFlags().Changed("Origin"){
		listOrigin, _ := cmd.Flags().GetString("Origin")
		listOriginAddr = &listOrigin
	}

	if rootCmd.PersistentFlags().Changed("URI"){
		listURI, _ := cmd.Flags().GetString("URI")
		listUriAddr = &listURI
	}

	if rootCmd.PersistentFlags().Changed("Collector"){
		listCollector, _ := cmd.Flags().GetString("Collector")
		listCollectorAddr = &listCollector
	}

	//This might not output anything as graphql would consider "" as a valid entry @abhi
	filter := model.HasSBOMSpec{
		Id: listIdAddr,
		Uri: listUriAddr,
		Algorithm: listAlgorithmAddr,
		Collector: listCollectorAddr,
		Origin: listOriginAddr,
		Digest: listDigestAddr,
		DownloadLocation: listDownloadLocationAddr,
	}

	//get all ingested SBOMs
	hasSBOMResponse, err := findHasSBOMBy( filter ,"", "",  ctx, gqlclient)
	if err != nil {
		fmt.Println("failed to lookup sbom: %v", err)
		os.Exit(1)
	}
	if len(hasSBOMResponse.HasSBOM) == 0 {
		fmt.Println("No SBOMs found with given filter")
		return
	}

	//print all ingested SBOMs
	all, _ := cmd.Flags().GetBool("all")
	maxprint, _ := cmd.Flags().GetInt("maxprint")
	printSBOMs(hasSBOMResponse.HasSBOM, all, maxprint)
	os.Exit(0)
}


func hasSBOMToGraph(cmd *cobra.Command, ctx context.Context, gqlclient graphql.Client) ( []graph.Graph[string, *Node]){
	slsas, errSlsa := cmd.Flags().GetStringSlice("slsa")
	sboms, errSbom := cmd.Flags().GetStringSlice("sboms")
	uri, _ := cmd.Flags().GetBool("uri")
	purl, _ := cmd.Flags().GetBool("purl")

	metadata, _ := cmd.Flags().GetBool("metadata")
	inclSoft, _ := cmd.Flags().GetBool("inclSoft")
	inclDeps, _ := cmd.Flags().GetBool("inclDeps")
	inclOccur, _ := cmd.Flags().GetBool("inclOccur")
	namespaces, _ := cmd.Flags().GetBool("namespaces")
	if namespaces {
		fmt.Println("Diff namespaces To be implemented, skipping...")
	}

	if (!metadata  && !inclSoft && !inclDeps && !inclOccur) {
		metadata = true
		inclSoft = true
		inclDeps = true
		inclOccur = true
	}


	verifyDiffFlags(slsas, sboms,  errSlsa, errSbom, uri, purl)
	var hasSBOMResponseOne *model.HasSBOMsResponse
	var hasSBOMResponseTwo *model.HasSBOMsResponse
	var err error

	if uri {
		hasSBOMResponseOne, err = findHasSBOMBy(model.HasSBOMSpec{} ,sboms[0],"",  ctx, gqlclient)
		if err != nil {
			fmt.Println("failed to lookup sbom: %s %v", sboms[0], err)
			os.Exit(1)
		}

		hasSBOMResponseTwo, err = findHasSBOMBy(model.HasSBOMSpec{},  sboms[1],"",  ctx, gqlclient)
		if err != nil {
			fmt.Println("failed to lookup sbom: %s %v", sboms[1], err)
			os.Exit(1)
		}
	} else if purl {
		hasSBOMResponseTwo, err = findHasSBOMBy( model.HasSBOMSpec{} ,"", sboms[0],  ctx, gqlclient)
		if err != nil {
			fmt.Println("failed to lookup sbom: %s %v", sboms[0], err)
			os.Exit(1)
		}
		hasSBOMResponseTwo, err = findHasSBOMBy( model.HasSBOMSpec{} ,"", sboms[1], ctx, gqlclient)
		if err != nil {
			fmt.Println("failed to lookup sbom: %s %v", sboms[1], err)
			os.Exit(1)
		}
	}
	if hasSBOMResponseOne == nil || hasSBOMResponseTwo == nil {
		fmt.Println("failed to lookup sboms")
		os.Exit(1)
	}
	if len(hasSBOMResponseOne.HasSBOM) == 0 || len(hasSBOMResponseTwo.HasSBOM) == 0 {
		fmt.Println("Failed to lookup sboms, one endpoint may not have sboms")
		os.Exit(1)
	}
	if len(hasSBOMResponseOne.HasSBOM) != 1 || len(hasSBOMResponseTwo.HasSBOM) != 1 {
		fmt.Println("Warning: Multiple sboms found for given purl or uri. Using first one")
	}
	hasSBOMOne :=  hasSBOMResponseOne.HasSBOM[0]
	hasSBOMTwo :=  hasSBOMResponseTwo.HasSBOM[0]
	//create graphs
	gOne := makeGraph(hasSBOMOne, metadata, inclSoft, inclDeps, inclOccur, namespaces)
	gTwo := makeGraph(hasSBOMTwo, metadata, inclSoft, inclDeps, inclOccur, namespaces)

	return []graph.Graph[string, *Node] {
		gOne,
		gTwo,
	}

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

func highlightDiff(gOne, gTwo graph.Graph[string, *Node]) (graph.Graph[string, *Node], HighlightedDiff ) {
	var diffList HighlightedDiff
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
					if key != "InclSoft"{
						overlay, ok1 := nodeOverlay.Attributes[key].(string) 
						g, ok2 := nodeG.Attributes[key].(string) 
						if ok1 && ok2 {
							diffList.MetadataMismatch = append(diffList.MetadataMismatch, key + "->" + g + "<->" + overlay)
						}
					}
					break
				}
			}
		}else {
			addGraphNode(g, overlayNodeID, "red") //change color to red
			diffList.MissingNodes = append(diffList.MissingNodes, overlayNodeID)
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
			diffList.MissingLinks = append(diffList.MissingLinks, []string{edge.Source, edge.Target})
		}
	}
	return g, diffList
}

func makeGraph(hasSBOM model.HasSBOMsHasSBOM, metadata, inclSoft, inclDeps, inclOccur, namespaces bool) graph.Graph[string, *Node] {

	g := graph.New(nodeHash, graph.Directed())
	
	//create HasSBOM node
	addGraphNode(g, "HasSBOM", "black")
	
	if metadata {
		//add metadata
		setNodeAttribute(g, "HasSBOM", "Id" , hasSBOM.Id)
		setNodeAttribute(g, "HasSBOM", "Algorithm" , hasSBOM.Algorithm)
		setNodeAttribute(g, "HasSBOM", "Collector" , hasSBOM.Collector)
		setNodeAttribute(g, "HasSBOM", "Digest" , hasSBOM.Digest)
		setNodeAttribute(g, "HasSBOM", "DownloadLocation" , hasSBOM.DownloadLocation)
		setNodeAttribute(g, "HasSBOM", "KnownSince" , hasSBOM.KnownSince.String())
		setNodeAttribute(g, "HasSBOM", "Origin" , hasSBOM.Origin)
		setNodeAttribute(g, "HasSBOM", "Uri" , hasSBOM.Uri)
		setNodeAttribute(g, "HasSBOM", "Subject" , *hasSBOM.Subject.GetTypename())
	}

	if inclOccur {
		//add included occurrences
		for _, occurrence := range hasSBOM.IncludedOccurrences {
			setNodeAttribute(g, "HasSBOM", "InclOccur-"+ occurrence.Id + "-Subject", occurrence.Subject)
			setNodeAttribute(g, "HasSBOM", "InclOccur-"+ occurrence.Id + "-Artifact-Id", occurrence.Artifact.Id)
			setNodeAttribute(g, "HasSBOM", "InclOccur-"+ occurrence.Id + "-Artifact-Algorithm", occurrence.Artifact.Algorithm)
			setNodeAttribute(g, "HasSBOM", "InclOccur-"+ occurrence.Id + "-Artifact-Digest", occurrence.Artifact.Digest)
			setNodeAttribute(g, "HasSBOM", "InclOccur-"+ occurrence.Id + "-Justification", occurrence.Justification)
			setNodeAttribute(g, "HasSBOM", "InclOccur-"+ occurrence.Id + "-Origin", occurrence.Origin)
			setNodeAttribute(g, "HasSBOM", "InclOccur-"+ occurrence.Id + "-Collector", occurrence.Collector)
		}	
	}

	
	if inclSoft {
		//add included software
		inclSoftMap :=  make(map[string]bool)

		for _, software := range hasSBOM.IncludedSoftware {
			inclSoftMap[*software.GetTypename()]= true
		}
		setNodeAttribute(g, "HasSBOM", "InclSoft", inclSoftMap)
	}

	
	if inclDeps {
		//add included dependencies
		for _, dependency := range hasSBOM.IncludedDependencies {
			packageId := dependency.Package.Id
			addGraphEdge(g, "HasSBOM" ,packageId,"black")
			includedDepsId := dependency.Id
			addGraphEdge(g, packageId, includedDepsId, "black")

			setNodeAttribute(g,  packageId, "Type" , dependency.Package.Type)
			
			if namespaces {
				//add namespaces
			}
			setNodeAttribute(g,  includedDepsId, "Justification" , dependency.Justification)

			if dependency.DependencyPackage.Id != "" {
				dependPkgId := dependency.DependencyPackage.Id
				addGraphEdge(g, includedDepsId, dependPkgId, "black")
				setNodeAttribute(g,  dependPkgId, "Type" , dependency.DependencyPackage.Type)
				setNodeAttribute(g,  dependPkgId, "DependencyType" , dependency.DependencyPackage.Type)
				setNodeAttribute(g,  dependPkgId, "VersionRange" , dependency.DependencyPackage.Type)
				setNodeAttribute(g,  dependPkgId, "Origin" , dependency.DependencyPackage.Type)
				setNodeAttribute(g,  dependPkgId, "Collector" , dependency.DependencyPackage.Type)
				
				if namespaces {
					//add namespaces
				}
			}
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
		color: color, 
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

	rootCmd.PersistentFlags().StringSlice("sboms", []string{}, "two sboms to find the diff between")
	rootCmd.PersistentFlags().StringSlice("slsa", []string{}, "two slsa to find the diff between")
	rootCmd.PersistentFlags().Bool("uri", false, "input is a URI")
	rootCmd.PersistentFlags().Bool("purl", false, "input is a pURL")
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
	rootCmd.PersistentFlags().Bool("all", false, "--all, lists all sboms matching filter criteria")
	rootCmd.PersistentFlags().Int("maxprint", PRINT_MAX, "max number of similar sboms to print")
	rootCmd.AddCommand(diffCmd)

}
