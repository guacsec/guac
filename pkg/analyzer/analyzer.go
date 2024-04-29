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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/Khan/genqlient/graphql"
	"github.com/dominikbraun/graph"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
)

type HighlightedDiff struct {
	MissingAddedRemovedLinks [][]string
	MissingAddedRemovedNodes []string
}

type HighlightedIntersect struct {
	MissingAddedRemovedLinks [][]string
	MissingAddedRemovedNodes []string
}

type HighlightedUnion struct {
	AddedLinks               [][]string
	MissingAddedRemovedNodes []string
}

type Node struct {
	ID         string
	Attributes map[string]interface{}
	color      string
	nodeType   string
}

type packageNameSpaces []model.AllPkgTreeNamespacesPackageNamespace

type packageNameSpacesNames []model.AllPkgTreeNamespacesPackageNamespaceNamesPackageName

type packageNameSpacesNamesVersions []model.AllPkgTreeNamespacesPackageNamespaceNamesPackageNameVersionsPackageVersion

type packageNameSpacesNamesVersionsQualifiers []model.AllPkgTreeNamespacesPackageNamespaceNamesPackageNameVersionsPackageVersionQualifiersPackageQualifier

func (a packageNameSpaces) Len() int           { return len(a) }
func (a packageNameSpaces) Less(i, j int) bool { return a[i].Namespace < a[j].Namespace }
func (a packageNameSpaces) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

func (a packageNameSpacesNames) Len() int           { return len(a) }
func (a packageNameSpacesNames) Less(i, j int) bool { return a[i].Name < a[j].Name }
func (a packageNameSpacesNames) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

func (a packageNameSpacesNamesVersions) Len() int           { return len(a) }
func (a packageNameSpacesNamesVersions) Less(i, j int) bool { return a[i].Version < a[j].Version }
func (a packageNameSpacesNamesVersions) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

func (a packageNameSpacesNamesVersionsQualifiers) Len() int           { return len(a) }
func (a packageNameSpacesNamesVersionsQualifiers) Less(i, j int) bool { return a[i].Key < a[j].Key }
func (a packageNameSpacesNamesVersionsQualifiers) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

func NodeHash(n *Node) string {
	return n.ID
}

func SetNodeAttribute(g graph.Graph[string, *Node], ID, key string, value interface{}) bool {
	node, err := g.Vertex(ID)
	if err != nil {
		return false
	}

	node.Attributes[key] = value
	return true
}

func GetNodeAttribute(g graph.Graph[string, *Node], ID, key string) (interface{}, error) {
	node, err := g.Vertex(ID)
	if err != nil {
		return nil, err
	}
	val, ok := node.Attributes[key]

	if !ok {
		return ID, nil
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
		foundHasSBOMPkg, err = model.HasSBOMs(ctx, gqlclient, model.HasSBOMSpec{Subject: &model.PackageOrArtifactSpec{Package: &model.PkgSpec{Id: &pkgResponse.Packages[0].Namespaces[0].Names[0].Versions[0].Id}}})
		if err != nil {
			return nil, fmt.Errorf("(purl)failed getting hasSBOM with error :%v", err)
		}
	} else if uri != "" {
		foundHasSBOMPkg, err = model.HasSBOMs(ctx, gqlclient, model.HasSBOMSpec{Uri: &uri})
		if err != nil {
			return nil, fmt.Errorf("(uri)failed getting hasSBOM  with error: %v", err)
		}
	} else if id != "" {
		foundHasSBOMPkg, err = model.HasSBOMs(ctx, gqlclient, model.HasSBOMSpec{Id: &id})
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

func dfsFindPaths(nodeID string, allNodeEdges map[string]map[string]graph.Edge[string], currentPath []string, allPaths *[][]string) {
	currentPath = append(currentPath, nodeID)

	// Check if the current node has any outgoing edges
	if val, ok := allNodeEdges[nodeID]; ok && len(val) == 0 {
		// If not, add the current path to the list of all paths
		*allPaths = append(*allPaths, currentPath)
		return
	}

	// Iterate over the adjacent nodes of the current node
	for target := range allNodeEdges[nodeID] {
		// Recursively explore the adjacent node
		dfsFindPaths(target, allNodeEdges, currentPath, allPaths)
	}
}

func FindPathsFromHasSBOMNode(g graph.Graph[string, *Node]) ([][]string, error) {

	var paths [][]string
	var currentPath []string
	allNodeEdges, err := g.AdjacencyMap()
	if err != nil {
		return paths, fmt.Errorf("error getting adjacency map")
	}
	if len(allNodeEdges) == 0 {
		return paths, nil
	}
	for nodeID := range allNodeEdges {
		if nodeID == "HasSBOM" {
			continue
		}
		val, err := GetNodeAttribute(g, nodeID, "nodeType")
		if err != nil {
			return paths, fmt.Errorf("error getting node type")
		}
		value, ok := val.(string)
		if !ok {
			return paths, fmt.Errorf("error casting node type to string")
		}
		if value == "Package" {
			//now start dfs
			dfsFindPaths(nodeID, allNodeEdges, currentPath, &paths)
		}
	}
	if len(paths) == 0 && len(allNodeEdges) > 1 {
		return paths, fmt.Errorf("paths 0, nodes > 1")
	}
	return paths, nil
}

func HighlightAnalysis(gOne, gTwo graph.Graph[string, *Node], action int) ([][]*Node, error) {
	pathsOne, errOne := FindPathsFromHasSBOMNode(gOne)
	pathsTwo, errTwo := FindPathsFromHasSBOMNode(gTwo)
	if errOne != nil || errTwo != nil {
		return [][]*Node{}, fmt.Errorf("error getting graph paths errOne-%v, errTwo-%v", errOne.Error(), errTwo.Error())
	}



	pathsOneStrings := concatenateLists(pathsOne)
	pathsTwoStrings := concatenateLists(pathsTwo)

	pathsOneMap := make(map[string][]*Node)
	pathsTwoMap := make(map[string][]*Node)

	var analysis [][]*Node

	for i := range pathsOne {
		nodes, err := nodeIDListToNodeList(gOne, pathsOne[i])
		if err != nil {
			return analysis, err
		}
		pathsOneMap[pathsOneStrings[i]] = nodes
	}

	for i := range pathsTwo {
		nodes, err := nodeIDListToNodeList(gTwo, pathsTwo[i])
		if err != nil {
			return analysis, err
		}
		pathsTwoMap[pathsTwoStrings[i]] = nodes
	}

	switch action {
	//0 is diff
	case 0:
		for key, val := range pathsOneMap {
			_, ok := pathsTwoMap[key]
			if !ok {
				//common
				analysis = append(analysis, val)
			}
		}

		for key, val := range pathsTwoMap {
			_, ok := pathsOneMap[key]
			if !ok {
				//common
				analysis = append(analysis, val)
			}
		}
	case 1:
		// 1 is intersect
		for key := range pathsOneMap {
			val, ok := pathsTwoMap[key]
			if ok {
				//common
				analysis = append(analysis, val)
			}
		}
	case 2:
		//2 is union
		for _, val := range pathsOneMap {
			analysis = append(analysis, val)
		}

		for key, val := range pathsTwoMap {
			_, ok := pathsOneMap[key]
			if !ok {
				//common
				analysis = append(analysis, val)
			}
		}
	}
	return analysis, nil
}

func MakeGraph(hasSBOM model.HasSBOMsHasSBOM, metadata, inclSoft, inclDeps, inclOccur, namespaces bool) (graph.Graph[string, *Node], error) {

	g := graph.New(NodeHash, graph.Directed())

	//create HasSBOM node
	AddGraphNode(g, "HasSBOM", "black")

	compareAll := !metadata && !inclSoft && !inclDeps && !inclOccur && !namespaces

	if metadata || compareAll {
		//add metadata
		if !(SetNodeAttribute(g, "HasSBOM", "Algorithm", hasSBOM.Algorithm) &&
			SetNodeAttribute(g, "HasSBOM", "Digest", hasSBOM.Digest) &&
			SetNodeAttribute(g, "HasSBOM", "Uri", hasSBOM.Uri)) {
			return g, fmt.Errorf("error setting metadata attribute(s)")
		}
	}
	//TODO: inclSoft and inclOccur

	if inclDeps || compareAll {
		//add included dependencies
		for _, dependency := range hasSBOM.IncludedDependencies {
			//package node
			//sort namespaces
			sort.Sort(packageNameSpaces(dependency.Package.Namespaces))
			message := dependency.Package.Type
			for _, namespace := range dependency.Package.Namespaces {
				message += namespace.Namespace
				sort.Sort(packageNameSpacesNames(namespace.Names))
				for _, name := range namespace.Names {
					message += name.Name
					sort.Sort(packageNameSpacesNamesVersions(name.Versions))
					for _, version := range name.Versions {
						message += version.Version
						message += version.Subpath
						sort.Sort(packageNameSpacesNamesVersionsQualifiers(version.Qualifiers))
						for _, outlier := range version.Qualifiers {
							message += outlier.Key
							message += outlier.Value
						}
					}
				}
			}

			if message == "" {
				return g, fmt.Errorf("encountered empty message for hashing")
			}

			hashValPackage := nodeHasher([]byte(message))
			_, err := g.Vertex(hashValPackage)

			if err != nil { //node does not exist
				AddGraphNode(g, hashValPackage, "black") // so, create a node
				AddGraphEdge(g, "HasSBOM", hashValPackage, "black")
				//set attributes here
				if !(SetNodeAttribute(g, hashValPackage, "nodeType", "Package") &&
					SetNodeAttribute(g, hashValPackage, "data", dependency.Package)) {
					return g, fmt.Errorf("error setting package node attribute(s)")
				}
			}

			//dependencyPackage node
			sort.Sort(packageNameSpaces(dependency.DependencyPackage.Namespaces))
			message = dependency.DependencyPackage.Type
			for _, namespace := range dependency.DependencyPackage.Namespaces {
				message += namespace.Namespace
				sort.Sort(packageNameSpacesNames(namespace.Names))
				for _, name := range namespace.Names {
					message += name.Name
					sort.Sort(packageNameSpacesNamesVersions(name.Versions))
					for _, version := range name.Versions {
						message += version.Version
						message += version.Subpath
						sort.Sort(packageNameSpacesNamesVersionsQualifiers(version.Qualifiers))
						for _, outlier := range version.Qualifiers {
							message += outlier.Key
							message += outlier.Value
						}
					}
				}
			}

			hashValDependencyPackage := nodeHasher([]byte(message))
			_, err = g.Vertex(hashValDependencyPackage)

			if err != nil { //node does not exist
				AddGraphNode(g, hashValDependencyPackage, "black")
				if !(SetNodeAttribute(g, hashValDependencyPackage, "nodeType", "DependencyPackage") &&
					SetNodeAttribute(g, hashValDependencyPackage, "data", dependency.DependencyPackage)) {
					return g, fmt.Errorf("error setting dependency package node attribute(s)")
				}
			}

			AddGraphEdge(g, hashValPackage, hashValDependencyPackage, "black")

		}
	}
	return g, nil
}
func nodeHasher(value []byte) string {
	hash := sha256.Sum256(value)
	return hex.EncodeToString(hash[:])
}

func AddGraphNode(g graph.Graph[string, *Node], _ID, color string) {
	var err error
	if _, err = g.Vertex(_ID); err == nil {
		return
	}

	newNode := &Node{
		ID:         _ID,
		color:      color,
		Attributes: make(map[string]interface{}),
	}

	err = g.AddVertex(newNode, graph.VertexAttribute("color", color))
	if err != nil {
		return
	}
}

func AddGraphEdge(g graph.Graph[string, *Node], from, to, color string) {
	AddGraphNode(g, from, "black")
	AddGraphNode(g, to, "black")

	_, err := g.Edge(from, to)
	if err == nil {
		return
	}

	if g.AddEdge(from, to, graph.EdgeAttribute("color", color)) != nil {
		return
	}
}

func GraphEqual(graphOne, graphTwo graph.Graph[string, *Node]) (bool, error) {
	gOneMap, errOne := graphOne.AdjacencyMap()

	gTwoMap, errTwo := graphTwo.AdjacencyMap()

	if errOne != nil || errTwo != nil {
		return false, fmt.Errorf("error getting graph nodes")
	}

	if len(gTwoMap) != len(gOneMap) {
		return false, fmt.Errorf("number of nodes not equal")
	}

	for key := range gOneMap {
		_, ok := gTwoMap[key]
		if !ok {
			return false, fmt.Errorf("missing key in map")
		}
	}

	edgesOne, errOne := graphOne.Edges()
	edgesTwo, errTwo := graphTwo.Edges()
	if errOne != nil || errTwo != nil {
		return false, fmt.Errorf("error getting edges")
	}

	if len(edgesOne) != len(edgesTwo) {
		return false, fmt.Errorf("edges not equal")
	}

	for _, edge := range edgesOne {
		_, err := graphTwo.Edge(edge.Source, edge.Target)
		if err != nil {
			return false, fmt.Errorf("edge not found Source - %s Target - %s", edge.Source, edge.Target)
		}
	}
	return true, nil

}

func GraphEdgesEqual(graphOne, graphTwo graph.Graph[string, *Node]) (bool, error) {

	pathsOne, errOne := FindPathsFromHasSBOMNode(graphOne)
	pathsTwo, errTwo := FindPathsFromHasSBOMNode(graphTwo)
	if errOne != nil || errTwo != nil {
		return false, fmt.Errorf("error getting graph paths errOne-%v, errTwo-%v", errOne.Error(), errTwo.Error())
	}

	if len(pathsOne) != len(pathsTwo) {
		return false, fmt.Errorf("paths not of equal length %v %v", len(pathsOne), len(pathsTwo))
	}

	pathsOneStrings := concatenateLists(pathsOne)
	pathsTwoStrings := concatenateLists(pathsTwo)

	sort.Strings(pathsTwoStrings)
	sort.Strings(pathsOneStrings)

	for i := range pathsOneStrings {
		if pathsOneStrings[i] != pathsTwoStrings[i] {
			return false, fmt.Errorf("paths differ %v", fmt.Sprintf("%v", i))
		}
	}

	return true, nil
}

func concatenateLists(list [][]string) []string {
	var concatenated []string
	for _, l := range list {
		concatenated = append(concatenated, strings.Join(l, ""))
	}
	return concatenated
}
func nodeIDListToNodeList(g graph.Graph[string, *Node], list []string) ([]*Node, error) {

	var nodeList []*Node
	for _, item := range list {
		nd, err := g.Vertex(item)
		if err != nil {
			return nodeList, err
		}
		nodeList = append(nodeList, nd)
	}
	return nodeList, nil
}
