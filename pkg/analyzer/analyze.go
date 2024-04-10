//
// Copyright 2024 The GUAC Authors.
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

package analyzer

import (
  "context"
  "fmt"

  "github.com/Khan/genqlient/graphql"
  "github.com/dominikbraun/graph"
  model "github.com/guacsec/guac/pkg/assembler/clients/generated"
  "github.com/guacsec/guac/pkg/assembler/helpers"
)

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

func NodeHash(n *Node) string {
  return n.ID
}

func SetNodeAttribute(g graph.Graph[string, *Node],ID, key string, value interface{}) bool {
  node, err := g.Vertex(ID)
  if err !=  nil {
	return false
  }

  node.Attributes[key] = value
  return true
}

func GetNodeAttribute(g graph.Graph[string, *Node],ID, key string) (interface{}, error) {
  node, err := g.Vertex(ID)
  if err !=  nil {
	return nil, err
  }
  val, ok := node.Attributes[key]

  if !ok {
    return ID, fmt.Errorf("node %s does not have attribute %s", ID, key)
  }
  return val, nil
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

func FindHasSBOMBy(filter model.HasSBOMSpec, uri, purl, id string, ctx context.Context, gqlclient graphql.Client) (*model.HasSBOMsResponse, error) {
  var foundHasSBOMPkg *model.HasSBOMsResponse
  var err error
  if purl != "" {
    pkgResponse, err := getPkgResponseFromPurl(ctx, gqlclient, purl)
    if err != nil {
      return nil, fmt.Errorf("getPkgResponseFromPurl - error: %v", err)
    }
    foundHasSBOMPkg, err = model.HasSBOMs(ctx, gqlclient, model.HasSBOMSpec{Subject: &model.PackageOrArtifactSpec{Package: &model.PkgSpec{Id: &pkgResponse.Packages[0].Namespaces[0].Names[0].Versions[0].Id}},
      })
    if err != nil {
      return nil, fmt.Errorf("(purl)failed getting hasSBOM with error :%v", err)
    }
  } else if uri != ""{
    foundHasSBOMPkg, err = model.HasSBOMs(ctx, gqlclient, model.HasSBOMSpec{Uri: &uri,})
    if err != nil {
      return nil, fmt.Errorf("(uri)failed getting hasSBOM  with error: %v", err)
    }
  }else if id != ""{
    foundHasSBOMPkg, err = model.HasSBOMs(ctx, gqlclient, model.HasSBOMSpec{Id: &id,})
    if err != nil {
      return nil, fmt.Errorf("(id)failed getting hasSBOM  with error: %v", err)
    }
  } else {
    foundHasSBOMPkg, err = model.HasSBOMs(ctx, gqlclient, filter)
    if err != nil {
      return nil, fmt.Errorf("(filter)failed getting hasSBOM  with error: %v", err)
    }
  }
  return foundHasSBOMPkg, nil
}


func HighlightAnalysis(gOne, gTwo graph.Graph[string, *Node], action int) (graph.Graph[string, *Node], HighlightedDiff, error ) {

  var big, small graph.Graph[string, *Node]
  var bigNodes, smallNodes map[string]map[string]graph.Edge[string]
  var analysisList HighlightedDiff
  gOneNodes,err := gOne.AdjacencyMap()
  if err != nil {
    return small, analysisList, fmt.Errorf("unable to get overlay AdjacencyMap: %v", err)
  }
  gTwoNodes, err := gTwo.AdjacencyMap()
  if err != nil {
	return small, analysisList, fmt.Errorf("unable to get base AdjacencyMap: %v", err)
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
        AddGraphNode(small, bigNodeId, "red") //change color to red
        diffList.MissingAddedRemovedNodes = append(diffList.MissingAddedRemovedNodes, bigNodeId)
      }
    }	

    //add edges not in diff but from g2
    edges, err := big.Edges()
    if err != nil {
      return small, analysisList, fmt.Errorf("error getting edges: %v", err)
    }

    for _, edge := range edges {
      _, err := small.Edge(edge.Source, edge.Target)
      if err != nil { //missing edge, add with red color
        AddGraphEdge(small, edge.Source, edge.Target, "red") //hmm how to add color?
        diffList.MissingAddedRemovedLinks = append(diffList.MissingAddedRemovedLinks, []string{edge.Source, edge.Target})
      }
    }

    return small, diffList, nil
  case 1:
    //intersect

    //remove edges present in small but not in big
    edges, err := small.Edges()
    if err != nil {
		return small, analysisList, fmt.Errorf("error getting edges: %v", err)
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
    return small, analysisList, nil
  case 2:
    //union

    //check if nodes are present in small but not in big
    for smallNodeId := range(smallNodes){
      if _, err = big.Vertex(smallNodeId); err != nil {
        AddGraphNode(big, smallNodeId, "red") //change color to red
        analysisList.MissingAddedRemovedNodes = append(analysisList.MissingAddedRemovedNodes, smallNodeId)
      }
    }	

    //add edges not in big but in small
    edges, err := small.Edges()
    if err != nil {
		return small, analysisList, fmt.Errorf("error getting edges: %v", err)
	}

    for _, edge := range edges {
      _, err := big.Edge(edge.Source, edge.Target)
      if err != nil { //missing edge, add with red color
        AddGraphEdge(big, edge.Source, edge.Target, "red") //hmm how to add color?
        analysisList.MissingAddedRemovedLinks = append(analysisList.MissingAddedRemovedLinks, []string{edge.Source, edge.Target})
      }
    }
    return big, analysisList, nil
  }
  return   nil, HighlightedDiff{}, nil
}

func MakeGraph(hasSBOM model.HasSBOMsHasSBOM, metadata, inclSoft, inclDeps, inclOccur, namespaces bool) (graph.Graph[string, *Node], error) {

  g := graph.New(NodeHash, graph.Directed())

  //create HasSBOM node
  AddGraphNode(g, "HasSBOM", "black")

  compareAll := !metadata && !inclSoft && !inclDeps && !inclOccur && !namespaces

  if metadata || compareAll {
    //add metadata
    if !(SetNodeAttribute(g, "HasSBOM", "Algorithm" , hasSBOM.Algorithm) &&
		SetNodeAttribute(g, "HasSBOM", "Collector" , hasSBOM.Collector)&&
		SetNodeAttribute(g, "HasSBOM", "Digest" , hasSBOM.Digest) &&
		SetNodeAttribute(g, "HasSBOM", "DownloadLocation" , hasSBOM.DownloadLocation) && 
		SetNodeAttribute(g, "HasSBOM", "KnownSince" , hasSBOM.KnownSince.String()) &&
		SetNodeAttribute(g, "HasSBOM", "Origin" , hasSBOM.Origin) &&
		SetNodeAttribute(g, "HasSBOM", "Subject" , *hasSBOM.Subject.GetTypename())) {
			return g, fmt.Errorf( "error setting metadata attribute")

	}
  }

  if inclOccur || compareAll {
    //add included occurrences
    for _, occurrence := range hasSBOM.IncludedOccurrences {
      if !(SetNodeAttribute(g, "HasSBOM", "InclOccur-"+ occurrence.Id + "-Subject", occurrence.Subject) &&
      SetNodeAttribute(g, "HasSBOM", "InclOccur-"+ occurrence.Id + "-Artifact-Id", occurrence.Artifact.Id) &&
      SetNodeAttribute(g, "HasSBOM", "InclOccur-"+ occurrence.Id + "-Artifact-Algorithm", occurrence.Artifact.Algorithm) &&
      SetNodeAttribute(g, "HasSBOM", "InclOccur-"+ occurrence.Id + "-Artifact-Digest", occurrence.Artifact.Digest) &&
      SetNodeAttribute(g, "HasSBOM", "InclOccur-"+ occurrence.Id + "-Justification", occurrence.Justification) &&
      SetNodeAttribute(g, "HasSBOM", "InclOccur-"+ occurrence.Id + "-Origin", occurrence.Origin) &&
      SetNodeAttribute(g, "HasSBOM", "InclOccur-"+ occurrence.Id + "-Collector", occurrence.Collector)) {
		return g, fmt.Errorf("error setting occurrence attributes" + occurrence.Id)
	  }
    }	
  }


  if inclSoft || compareAll {
    //add included software
    inclSoftMap :=  make(map[string]bool)

    for _, software := range hasSBOM.IncludedSoftware {
      inclSoftMap[*software.GetTypename()]= true
    }
    if !SetNodeAttribute(g, "HasSBOM", "InclSoft", inclSoftMap) {
		return g, fmt.Errorf("error setting included software attributes")
	}
  }


  if inclDeps || compareAll {
    //add included dependencies
    for _, dependency := range hasSBOM.IncludedDependencies {
      packageId := dependency.Package.Id
      AddGraphEdge(g, "HasSBOM" ,packageId,"black")
      includedDepsId := dependency.Id
      AddGraphEdge(g, packageId, includedDepsId, "black")
      SetNodeAttribute(g,  packageId, "Type" , dependency.Package.Type)
      if namespaces || compareAll {
        //add namespaces	
        if !SetNodeAttribute(g,  packageId, "Namespace[0]" , dependency.Package.Namespaces[0].Names[0].Name){
			return g, fmt.Errorf("error setting namespace attribute")
        	}
	}
      

      if !(SetNodeAttribute(g,  includedDepsId, "Justification" , dependency.Justification) &&
      SetNodeAttribute(g,  includedDepsId, "DependencyType" , dependency.DependencyType) &&
      SetNodeAttribute(g,  includedDepsId, "VersionRange" , dependency.VersionRange) &&
      SetNodeAttribute(g,  includedDepsId, "Origin" , dependency.Origin) &&
      SetNodeAttribute(g,  includedDepsId, "Collector" , dependency.Collector)) {
		return g, fmt.Errorf("error setting dependency attributes")
	  }


      if dependency.DependencyPackage.Id != "" {
        dependPkgId := dependency.DependencyPackage.Id
        AddGraphEdge(g, includedDepsId, dependPkgId, "black")
        SetNodeAttribute(g,  dependPkgId, "Type" , dependency.DependencyPackage.Type)

        if namespaces  || compareAll {
          //add namespaces	
          SetNodeAttribute(g,  dependPkgId, "Namespace[0]" , dependency.DependencyPackage.Namespaces[0].Names[0].Name)
        }
      }

    
  }
}
  return g, nil
}




func AddGraphNode(g graph.Graph[string, *Node],_ID, color string) {
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
    return
  }
}

func AddGraphEdge(g graph.Graph[string, *Node], from, to, color string){
  AddGraphNode(g, from, "black")
  AddGraphNode(g, to, "black")

  _, err  := g.Edge(from, to)
  if err == nil {
    return
  }

  if g.AddEdge(from, to, graph.EdgeAttribute("color", color)) != nil {
	return
  }
}

