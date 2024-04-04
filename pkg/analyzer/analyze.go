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

package guacanalyze

import (
  "context"
  "fmt"

  "os"

  "github.com/Khan/genqlient/graphql"
  "github.com/dominikbraun/graph"
  "github.com/dominikbraun/graph/draw"
  model "github.com/guacsec/guac/pkg/assembler/clients/generated"
  "github.com/guacsec/guac/pkg/assembler/helpers"

  "github.com/olekukonko/tablewriter"
  "github.com/spf13/cobra"

  "k8s.io/apimachinery/pkg/util/rand"
)

const PRINT_MAX = 20

type HighlightedDiff struct {
  MissingAddedRemovedLinks [][]string
  MissingAddedRemovedNodes []string
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

func getNodeAttribute(g graph.Graph[string, *Node],ID, key string) interface{} {
  var (
    err error
    node *Node
  )
  if node, err = g.Vertex(ID); err !=  nil {
    fmt.Println("Error getting node attribute", err)
    os.Exit(1)
  }
  val, ok := node.Attributes[key]

  if  !ok {
    return ID
  }
  return val
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

func findHasSBOMBy(filter model.HasSBOMSpec, uri, purl, id string, ctx context.Context, gqlclient graphql.Client) (*model.HasSBOMsResponse, error) {
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
  }else if id != ""{
    foundHasSBOMPkg, err = model.HasSBOMs(ctx, gqlclient, model.HasSBOMSpec{Id: &id,})
    if err != nil {
      fmt.Printf("(id)failed getting hasSBOM  with error: %v", err)
      return nil, err
    }
  } else {
    foundHasSBOMPkg, err = model.HasSBOMs(ctx, gqlclient, filter)
    if err != nil {
      fmt.Printf("(filter)failed getting hasSBOM  with error: %v", err)
      return nil, err
    }
  }
  return foundHasSBOMPkg, nil
}

func verifyAnalyzeFlags(slsas, sboms []string,  errSlsa, errSbom error, uri, purl, id bool) {

  if (errSlsa != nil && errSbom != nil) || (len(slsas) ==0  && len(sboms) == 0 ){
    fmt.Println("Must specify slsa or sboms ")
    os.Exit(0)
  }

  if len(slsas) >0  && len(sboms) >0 {
    fmt.Println("Must either specify slsa or sbom")
    os.Exit(0)
  }

  if errSlsa == nil && (len(slsas) <= 1|| len(slsas) > 2) && len(sboms) == 0{
    fmt.Println("Must specify exactly two slsas to analyze, specified", len(slsas))
    os.Exit(0)
  }

  if errSbom == nil && (len(sboms) <= 1|| len(sboms) > 2) && len(slsas) == 0{
    fmt.Println("Must specify exactly two sboms to analyze, specified", len(sboms))
    os.Exit(0)
  }

  if errSlsa == nil && len(slsas) == 2 {
    fmt.Println("slsa diff to be implemented.")
    os.Exit(0)
  }

  if !uri && !purl && !id {
    fmt.Println("Must provide one of --uri or --purl")
    os.Exit(0)
  }

  if uri && purl  || uri && id || purl && id {
    fmt.Println("Must provide only one of --uri or --purl")
    os.Exit(0)
  }
}


func GenerateAnalysisOutput(analysisGraph graph.Graph[string, *Node], diffList HighlightedDiff, all, dot bool, maxprint, action int, gqlclient graphql.Client){
  //Create dot file
  createGraphDotFile(dot, analysisGraph)
  //print to stdout
  printHighlightedAnalysis(dot, diffList, all, maxprint, action, analysisGraph )
}
func max(nums []int) int {
  if len(nums) == 0 {
    return 0
  }
  max := nums[0]
  for _, num := range nums[1:] {
    if num > max {
      max = num
    }
  }
  return max
}
func printHighlightedAnalysis(dot bool,diffList HighlightedDiff, all bool, maxprint, action int,  analysisGraph graph.Graph[string, *Node]){

  if dot {
    return 
  }
  //use action here to do different things
  if action == 0 {
    metadataTable := tablewriter.NewWriter(os.Stdout)
    metadataTable.SetHeader([]string{ "Metadata"})
    for _, metadata := range diffList.MetadataMismatch {
      if (!all && len(diffList.MetadataMismatch) == maxprint){
        break
      }
      metadataTable.Append([]string{metadata})
    }
    metadataTable.SetAlignment(tablewriter.ALIGN_LEFT)
    metadataTable.Render()
  }


  table := tablewriter.NewWriter(os.Stdout)

  switch action { 
  case 0:
    table.SetHeader([]string{ "Missing Nodes", "Missing Links"})
  case 1:
    table.SetHeader([]string{ "Common Nodes", "Common Links"})
  case 2:
    table.SetHeader([]string{ "Added Nodes", "Added Links"})
  }


  max :=  max([]int{len(diffList.MissingAddedRemovedNodes), len(diffList.MissingAddedRemovedLinks)})

  for i :=0 ; i< max; i++{

    if (!all && i+1 == maxprint){
      break
    }

    var appendList []string


    if i< len(diffList.MissingAddedRemovedNodes){
      namespace, ok := getNodeAttribute(analysisGraph,diffList.MissingAddedRemovedNodes[i], "Namespace[0]").(string)

      if !ok {
        fmt.Println("Error getting node namespace attribute")
        os.Exit(1)
      }
      appendList = append(appendList,namespace)
    } else {
      appendList = append(appendList, "")
    }

    if i< len(diffList.MissingAddedRemovedLinks){
      namespaceOne, okOne := getNodeAttribute(analysisGraph,diffList.MissingAddedRemovedLinks[i][0], "Namespace[0]").(string)
      namespaceTwo, okTwo := getNodeAttribute(analysisGraph,diffList.MissingAddedRemovedLinks[i][1], "Namespace[0]").(string)

      if !okOne || !okTwo {
        fmt.Println("Error getting node namespace attribute")
        os.Exit(1)
      }

      appendList = append(appendList, namespaceOne + "--->"+namespaceTwo)
    }else {
      appendList = append(appendList, "")
    }
    table.Append(appendList)
  }



  table.SetAlignment(tablewriter.ALIGN_LEFT)
  table.Render()
  if (!all && max > maxprint){
    fmt.Println("Run with --all to see full list")
  }
}

func HasSBOMToGraph(cmd *cobra.Command, ctx context.Context, gqlclient graphql.Client) ( []graph.Graph[string, *Node]){
  slsas, errSlsa := cmd.Flags().GetStringSlice("slsa")
  sboms, errSbom := cmd.Flags().GetStringSlice("sboms")
  uri, _ := cmd.Flags().GetBool("uri")
  purl, _ := cmd.Flags().GetBool("purl")

  metadata, _ := cmd.Flags().GetBool("metadata")
  inclSoft, _ := cmd.Flags().GetBool("inclSoft")
  inclDeps, _ := cmd.Flags().GetBool("inclDeps")
  inclOccur, _ := cmd.Flags().GetBool("inclOccur")
  namespaces, _ := cmd.Flags().GetBool("namespaces")

  id, _ := cmd.Flags().GetBool("id")

  verifyAnalyzeFlags(slsas, sboms,  errSlsa, errSbom, uri, purl, id)
  var hasSBOMResponseOne *model.HasSBOMsResponse
  var hasSBOMResponseTwo *model.HasSBOMsResponse
  var err error

  if uri {
    hasSBOMResponseOne, err = findHasSBOMBy(model.HasSBOMSpec{} ,sboms[0],"", "", ctx, gqlclient)
    if err != nil {
      fmt.Println("(uri)failed to lookup sbom:", sboms[0], err)
      os.Exit(1)
    }

    hasSBOMResponseTwo, err = findHasSBOMBy(model.HasSBOMSpec{},  sboms[1],"", "", ctx, gqlclient)
    if err != nil {
      fmt.Println("(uri)failed to lookup sbom:", sboms[1], err)
      os.Exit(1)
    }
  } else if purl {
    hasSBOMResponseOne, err = findHasSBOMBy( model.HasSBOMSpec{} ,"", sboms[0], "", ctx, gqlclient)
    if err != nil {
      fmt.Println("(purl)failed to lookup sbom:", sboms[0], err)
      os.Exit(1)
    }
    hasSBOMResponseTwo, err = findHasSBOMBy( model.HasSBOMSpec{} ,"", sboms[1],"", ctx, gqlclient)
    if err != nil {
      fmt.Println("(purl)failed to lookup sbom:", sboms[1], err)
      os.Exit(1)
    }
  } else if id {
    hasSBOMResponseOne, err = findHasSBOMBy( model.HasSBOMSpec{} ,"", "", sboms[0], ctx, gqlclient)
    if err != nil {
      fmt.Println("(id)failed to lookup sbom:", sboms[0], err)
      os.Exit(1)
    }
    hasSBOMResponseTwo, err = findHasSBOMBy( model.HasSBOMSpec{} ,"", "", sboms[1] ,ctx, gqlclient)
    if err != nil {
      fmt.Println("(id)failed to lookup sbom:", sboms[1], err)
      os.Exit(1)
    }

  }
  if hasSBOMResponseOne == nil || hasSBOMResponseTwo == nil {
    fmt.Println("failed to lookup sboms: nil",)
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

func createGraphDotFile(dot bool, g graph.Graph[string, *Node]){
  if !dot {
    return
  }
  filename := rand.String(10)+".dot"
  file, _ := os.Create(filename)
  err := draw.DOT(g, file)
  if err!= nil {
    fmt.Println("Error creating dot file:", err)
    os.Exit(1)
  }
  fmt.Println(filename)
}

func HighlightAnalysis(gOne, gTwo graph.Graph[string, *Node], action int) (graph.Graph[string, *Node], HighlightedDiff ) {

  var big, small graph.Graph[string, *Node]
  var bigNodes, smallNodes map[string]map[string]graph.Edge[string]
  var analysisList HighlightedDiff
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
    big = gTwo
    bigNodes = gTwoNodes
    small = gOne
    smallNodes = gOneNodes
  } else if len(gOneNodes) > len(gTwoNodes) {
    big = gOne
    small = gTwo
    bigNodes = gOneNodes
    smallNodes = gTwoNodes
  } else {
    big = gTwo
    bigNodes = gTwoNodes
    small = gOne
    smallNodes = gOneNodes
  }

  if err != nil {
    fmt.Println("Unable to clone graph:", err)
    os.Exit(1)
  }

  switch action {
  //0 is diff
  case 0:
    var diffList HighlightedDiff
    //check nodes and their data
    for bigNodeId := range(bigNodes){
      if _, err = small.Vertex(bigNodeId); err == nil {
        nodeBig, _ := big.Vertex(bigNodeId)
        nodeSmall, _ := small.Vertex(bigNodeId)
        //TODO: if nodes are not equal we need to highlight which attribute is different 
        for key := range nodeBig.Attributes {
          if key != "InclSoft"{
            overlay, ok1 := nodeBig.Attributes[key].(string) 
            g, ok2 := nodeSmall.Attributes[key].(string) 
            if (ok1 && ok2 && g != overlay) {
              //TODO: change color of node here

              diffList.MetadataMismatch = append(diffList.MetadataMismatch, key + "->" + g + "<->" + overlay)
            }
          }else {
            overlay, ok1 := nodeBig.Attributes[key].(map[string]bool) 
            g, ok2 := nodeSmall.Attributes[key].(map[string]bool) 
            if ok1 && ok2 {
              //compare here

              for _key := range overlay {
                _, _ok1 := g[_key]
                _, _ok2 :=  overlay[_key]
                if !(_ok1 && _ok2) {
                  diffList.MetadataMismatch = append(diffList.MetadataMismatch, "IncludedSoftware" + "-Missing->" + _key)
                }
              }
            }
          }
        }
      }else {
        addGraphNode(small, bigNodeId, "red") //change color to red
        diffList.MissingAddedRemovedNodes = append(diffList.MissingAddedRemovedNodes, bigNodeId)
      }
    }	

    //add edges not in diff but from g2
    edges, err := big.Edges()
    if err != nil {
      fmt.Println("Error getting edges:", err)
      os.Exit(1)
    }

    for _, edge := range edges {
      _, err := small.Edge(edge.Source, edge.Target)
      if err != nil { //missing edge, add with red color
        addGraphEdge(small, edge.Source, edge.Target, "red") //hmm how to add color?
        diffList.MissingAddedRemovedLinks = append(diffList.MissingAddedRemovedLinks, []string{edge.Source, edge.Target})
      }
    }

    return small, diffList
  case 1:
    //intersect

    //remove edges present in small but not in big
    edges, err := small.Edges()
    if err != nil {
      fmt.Println("Error getting edges:", err)
      os.Exit(1)
    }

    for _, edge := range edges {
      if edge.Source == "HasSBOM" || edge.Target == "HasSBOM" {
        continue
      }
      _, err := big.Edge(edge.Source, edge.Target)
      if err != nil { 

        if small.RemoveEdge(edge.Source, edge.Target) != nil {
			continue
		}
      }else {
        analysisList.MissingAddedRemovedLinks = append(analysisList.MissingAddedRemovedLinks, []string{edge.Source, edge.Target})
      }
    }

    //remove nodes present in small but not in big
    for smallNodeId := range(smallNodes){
      if smallNodeId == "HasSBOM" {
        continue
      }
      if _, err = big.Vertex(smallNodeId); err != nil {

       if  small.RemoveVertex(smallNodeId) != nil {
		continue
	   }

      }else{
        analysisList.MissingAddedRemovedNodes = append(analysisList.MissingAddedRemovedNodes, smallNodeId)
      }
    }	
    return small, analysisList
  case 2:
    //union

    //check if nodes are present in small but not in big
    for smallNodeId := range(smallNodes){
      if _, err = big.Vertex(smallNodeId); err != nil {
        addGraphNode(big, smallNodeId, "red") //change color to red
        analysisList.MissingAddedRemovedNodes = append(analysisList.MissingAddedRemovedNodes, smallNodeId)
      }
    }	

    //add edges not in big but in small
    edges, err := small.Edges()
    if err != nil {
      fmt.Println("Error getting edges:", err)
      os.Exit(1)
    }

    for _, edge := range edges {
      _, err := big.Edge(edge.Source, edge.Target)
      if err != nil { //missing edge, add with red color
        addGraphEdge(big, edge.Source, edge.Target, "red") //hmm how to add color?
        analysisList.MissingAddedRemovedLinks = append(analysisList.MissingAddedRemovedLinks, []string{edge.Source, edge.Target})
      }
    }
    return big, analysisList
  }
  return   nil, HighlightedDiff{}
}

func makeGraph(hasSBOM model.HasSBOMsHasSBOM, metadata, inclSoft, inclDeps, inclOccur, namespaces bool) graph.Graph[string, *Node] {

  g := graph.New(nodeHash, graph.Directed())

  //create HasSBOM node
  addGraphNode(g, "HasSBOM", "black")

  compareAll := !metadata && !inclSoft && !inclDeps && !inclOccur && !namespaces

  if metadata || compareAll {
    //add metadata
    setNodeAttribute(g, "HasSBOM", "Algorithm" , hasSBOM.Algorithm)
    setNodeAttribute(g, "HasSBOM", "Collector" , hasSBOM.Collector)
    setNodeAttribute(g, "HasSBOM", "Digest" , hasSBOM.Digest)
    setNodeAttribute(g, "HasSBOM", "DownloadLocation" , hasSBOM.DownloadLocation)
    setNodeAttribute(g, "HasSBOM", "KnownSince" , hasSBOM.KnownSince.String())
    setNodeAttribute(g, "HasSBOM", "Origin" , hasSBOM.Origin)
    setNodeAttribute(g, "HasSBOM", "Subject" , *hasSBOM.Subject.GetTypename())
  }

  if inclOccur || compareAll {
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


  if inclSoft || compareAll {
    //add included software
    inclSoftMap :=  make(map[string]bool)

    for _, software := range hasSBOM.IncludedSoftware {
      inclSoftMap[*software.GetTypename()]= true
    }
    setNodeAttribute(g, "HasSBOM", "InclSoft", inclSoftMap)
  }


  if inclDeps || compareAll {
    //add included dependencies
    for _, dependency := range hasSBOM.IncludedDependencies {
      packageId := dependency.Package.Id
      addGraphEdge(g, "HasSBOM" ,packageId,"black")
      includedDepsId := dependency.Id
      addGraphEdge(g, packageId, includedDepsId, "black")
      setNodeAttribute(g,  packageId, "Type" , dependency.Package.Type)
      if namespaces || compareAll {
        //add namespaces	
        setNodeAttribute(g,  packageId, "Namespace[0]" , dependency.Package.Namespaces[0].Names[0].Name)
      }


      setNodeAttribute(g,  includedDepsId, "Justification" , dependency.Justification)
      setNodeAttribute(g,  includedDepsId, "DependencyType" , dependency.DependencyType)
      setNodeAttribute(g,  includedDepsId, "VersionRange" , dependency.VersionRange)
      setNodeAttribute(g,  includedDepsId, "Origin" , dependency.Origin)
      setNodeAttribute(g,  includedDepsId, "Collector" , dependency.Collector)


      if dependency.DependencyPackage.Id != "" {
        dependPkgId := dependency.DependencyPackage.Id
        addGraphEdge(g, includedDepsId, dependPkgId, "black")
        setNodeAttribute(g,  dependPkgId, "Type" , dependency.DependencyPackage.Type)

        if namespaces  || compareAll {
          //add namespaces	
          setNodeAttribute(g,  dependPkgId, "Namespace[0]" , dependency.DependencyPackage.Namespaces[0].Names[0].Name)
        }
      }
    }
  }
  return g
}

func addGraphNode(g graph.Graph[string, *Node],_ID, color string) {
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
  if g.AddEdge(from, to, graph.EdgeAttribute("color", color)) != nil {
	return
  }

}

