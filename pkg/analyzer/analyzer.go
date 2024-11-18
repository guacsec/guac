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
	"math"
	"sync"

	"sort"
	"strings"

	"github.com/Khan/genqlient/graphql"
	"github.com/dominikbraun/graph"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/sergi/go-diff/diffmatchpatch"
)

type NodeType int
type Action int

const (
	ColorReset = "\033[0m"
	ColorRed   = "\033[31m"
	ColorGreen = "\033[32m"
	ColorWhite = "\033[37m"
)

var shaPatterns = []string{
	`^[a-fA-F0-9]{40}$`,  // SHA-1
	`^[a-fA-F0-9]{56}$`,  // SHA-224
	`^[a-fA-F0-9]{64}$`,  // SHA-256
	`^[a-fA-F0-9]{96}$`,  // SHA-384
	`^[a-fA-F0-9]{128}$`, // SHA-512
}

const (
	Pkg NodeType = iota
	DepPkg
)

func (n NodeType) String() string {
	return [...]string{"Pkg", "DepPkg"}[n]
}

const (
	Difference Action = iota
	Intersection
	Union
)

func (a Action) String() string {
	return [...]string{"Difference", "Intersection", "Union"}[a]
}

type Node struct {
	ID         string
	Attributes map[string]string
	Pkg        model.AllIsDependencyTreePackage
	NodeType   string
	DepPkg     model.AllIsDependencyTreeDependencyPackage
	Color      string
}

type DiffResult struct {
	Paths []DiffedPath
	Nodes map[string]DiffedNodePair
}

type EqualDifferencesPaths struct {
	Diffs [][]string
	Path  []*Node
	Index int
}

type DiffedNodePair struct {
	NodeOne *Node
	NodeTwo *Node
	Count   int
}

type DiffedPath struct {
	PathOne   []*Node
	PathTwo   []*Node
	Diffs     [][]string
	NodeDiffs []Node
	Index     int
	DiffNum   int
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

		node, err := g.Vertex(nodeID)

		if err != nil {
			return paths, fmt.Errorf("error getting node type")
		}

		if node.NodeType == "Package" {
			//now start dfs
			dfsFindPaths(nodeID, allNodeEdges, currentPath, &paths)
		}
	}
	if len(paths) == 0 && len(allNodeEdges) > 1 {
		return paths, fmt.Errorf("paths 0, nodes > 1")
	}
	return paths, nil
}

func HighlightAnalysis(gOne, gTwo graph.Graph[string, *Node], action Action) ([][]*Node, [][]*Node, error) {
	pathsOne, errOne := FindPathsFromHasSBOMNode(gOne)
	pathsTwo, errTwo := FindPathsFromHasSBOMNode(gTwo)

	if errOne != nil || errTwo != nil {
		return [][]*Node{}, [][]*Node{}, fmt.Errorf("error getting graph paths errOne-%v, errTwo-%v", errOne.Error(), errTwo.Error())
	}

	pathsOneStrings := concatenateLists(pathsOne)
	pathsTwoStrings := concatenateLists(pathsTwo)

	pathsOneMap := make(map[string][]*Node)
	pathsTwoMap := make(map[string][]*Node)

	var analysisOne, analysisTwo [][]*Node

	//create a map so that we are only using unique paths.
	for i := range pathsOne {
		nodes, err := nodeIDListToNodeList(gOne, pathsOne[i])
		if err != nil {
			return analysisOne, analysisTwo, err
		}
		_, ok := pathsOneMap[pathsOneStrings[i]]
		if !ok {
			pathsOneMap[pathsOneStrings[i]] = nodes
		}
	}

	for i := range pathsTwo {
		nodes, err := nodeIDListToNodeList(gTwo, pathsTwo[i])
		if err != nil {
			return analysisOne, analysisTwo, err
		}
		_, ok := pathsTwoMap[pathsTwoStrings[i]]
		if !ok {
			pathsTwoMap[pathsTwoStrings[i]] = nodes
		}
	}

	switch action {

	case Difference:
		for key, val := range pathsOneMap {
			_, ok := pathsTwoMap[key]
			if !ok {

				analysisOne = append(analysisOne, val)
			}
		}

		for key, val := range pathsTwoMap {
			_, ok := pathsOneMap[key]
			if !ok {

				analysisTwo = append(analysisTwo, val)
			}
		}

	case Intersection:
		for key := range pathsOneMap {
			val, ok := pathsTwoMap[key]
			if ok {
				analysisOne = append(analysisOne, val)
			}
		}

	case Union:

		for _, val := range pathsOneMap {
			analysisOne = append(analysisOne, val)
		}

		for key, val := range pathsTwoMap {
			_, ok := pathsOneMap[key]
			if !ok {
				analysisTwo = append(analysisTwo, val)
			}
		}

	}

	return analysisOne, analysisTwo, nil
}

func MakeGraph(hasSBOM model.HasSBOMsHasSBOM, metadata, inclSoft, inclDeps, inclOccur, namespaces bool) (graph.Graph[string, *Node], error) {

	g := graph.New(NodeHash, graph.Directed())

	//create HasSBOM node
	AddGraphNode(g, "HasSBOM", "black")

	compareAll := !metadata && !inclSoft && !inclDeps && !inclOccur && !namespaces

	if metadata || compareAll {
		//add metadata
		node, err := g.Vertex("HasSBOM")
		if err != nil {
			return g, fmt.Errorf("hasSBOM node not found")
		}
		node.Attributes = map[string]string{}
		node.Attributes["Algorithm"] = hasSBOM.Algorithm
		node.Attributes["Digest"] = hasSBOM.Digest
		node.Attributes["Uri"] = hasSBOM.Uri
	}

	if inclDeps || compareAll {
		//add included dependencies
		//sort dependencies here
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
				node, err := g.Vertex(hashValPackage)
				if err != nil {
					return g, fmt.Errorf("newly created node not found in graph")
				}
				node.NodeType = "Package"
				node.Pkg = dependency.Package
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
				node, err := g.Vertex(hashValDependencyPackage)
				if err != nil {
					return g, fmt.Errorf("newly created node not found in graph")
				}
				node.NodeType = "DependencyPackage"
				node.DepPkg = dependency.DependencyPackage
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

func AddGraphNode(g graph.Graph[string, *Node], id, color string) {
	var err error
	if _, err = g.Vertex(id); err == nil {
		return
	}

	newNode := &Node{
		ID:    id,
		Color: color,
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

func DiffMissingName(dmp *diffmatchpatch.DiffMatchPatch, name model.AllPkgTreeNamespacesPackageNamespaceNamesPackageName) model.AllPkgTreeNamespacesPackageNamespaceNamesPackageName {
	name.Name = ComputeStringDiffs(dmp, name.Name, "")
	for k, version := range name.Versions {
		name.Versions[k].Version = ComputeStringDiffs(dmp, version.Version, "")
		for l, qualifier := range version.Qualifiers {
			name.Versions[k].Qualifiers[l].Key = ComputeStringDiffs(dmp, qualifier.Key, "")
			name.Versions[k].Qualifiers[l].Value = ComputeStringDiffs(dmp, qualifier.Value, "")
		}
	}
	return name
}

func DiffMissingVersion(dmp *diffmatchpatch.DiffMatchPatch, version model.AllPkgTreeNamespacesPackageNamespaceNamesPackageNameVersionsPackageVersion) model.AllPkgTreeNamespacesPackageNamespaceNamesPackageNameVersionsPackageVersion {
	version.Version = ComputeStringDiffs(dmp, version.Version, "")
	for l, qualifier := range version.Qualifiers {
		version.Qualifiers[l].Key = ComputeStringDiffs(dmp, qualifier.Key, "")
		version.Qualifiers[l].Value = ComputeStringDiffs(dmp, qualifier.Value, "")
	}
	return version
}

func DiffMissingQualifier(dmp *diffmatchpatch.DiffMatchPatch, qualifier model.AllPkgTreeNamespacesPackageNamespaceNamesPackageNameVersionsPackageVersionQualifiersPackageQualifier) model.AllPkgTreeNamespacesPackageNamespaceNamesPackageNameVersionsPackageVersionQualifiersPackageQualifier {
	qualifier.Key = ComputeStringDiffs(dmp, qualifier.Key, "")
	qualifier.Value = ComputeStringDiffs(dmp, qualifier.Value, "")
	return qualifier
}

func DiffMissingNamespace(dmp *diffmatchpatch.DiffMatchPatch, namespace model.AllPkgTreeNamespacesPackageNamespace) model.AllPkgTreeNamespacesPackageNamespace {
	namespace.Namespace = ComputeStringDiffs(dmp, namespace.Namespace, "")
	for j, name := range namespace.Names {
		namespace.Names[j].Name = ComputeStringDiffs(dmp, name.Name, "")
		for k, version := range name.Versions {
			namespace.Names[j].Versions[k].Version = ComputeStringDiffs(dmp, version.Version, "")
			for l, qualifier := range version.Qualifiers {
				namespace.Names[j].Versions[k].Qualifiers[l].Key = ComputeStringDiffs(dmp, qualifier.Key, "")
				namespace.Names[j].Versions[k].Qualifiers[l].Value = ComputeStringDiffs(dmp, qualifier.Value, "")
			}
		}
	}
	return namespace
}



func ComputeStringDiffs(dmp *diffmatchpatch.DiffMatchPatch, text1, text2 string) string {

	// Enable line mode for faster processing on large texts
	diffs := dmp.DiffMain(text1, text2, true)
	diffs = dmp.DiffCleanupSemantic(diffs) // Optional: Clean up diff for better readability
	diffString := FormatDiffs(diffs)
	return diffString
}

func FormatDiffsTableWriter(diffs []diffmatchpatch.Diff) string {

	var parts []string
	// Precompile color codes into variables
	colorGreen := ColorGreen
	colorRed := ColorRed
	colorWhite := ColorWhite
	colorReset := ColorReset

	for _, diff := range diffs {
		var prefix string
		switch diff.Type {
		case diffmatchpatch.DiffInsert:
			prefix = colorGreen + "+" + CheckEmptyTrim(diff.Text) + colorReset
		case diffmatchpatch.DiffDelete:
			prefix = colorRed + "-" + CheckEmptyTrim(diff.Text) + colorReset
		case diffmatchpatch.DiffEqual:
			prefix = colorWhite + " " + CheckEmptyTrim(diff.Text) + colorReset
		}
		parts = append(parts, prefix)
	}
	diffString := strings.Join(parts, "")
	return diffString
}

func FormatDiffs(diffs []diffmatchpatch.Diff) string {

	var parts []string
	// Precompile color codes into variables
	colorGreen := "[green]"
	colorRed := "[red]"
	colorWhite := "[white]"

	for _, diff := range diffs {
		var prefix string
		switch diff.Type {
		case diffmatchpatch.DiffInsert:
			prefix = colorGreen + "+" + CheckEmptyTrim(diff.Text) 
		case diffmatchpatch.DiffDelete:
			prefix = colorRed + "-" + CheckEmptyTrim(diff.Text) 
		case diffmatchpatch.DiffEqual:
			prefix = colorWhite + " " + CheckEmptyTrim(diff.Text) 
		}
		parts = append(parts, prefix)
	}
	diffString := strings.Join(parts, "")
	return diffString
}

func compareNodes(dmp *diffmatchpatch.DiffMatchPatch, nodeOne, nodeTwo Node) (Node, []string, error) {
	var diffs []string
	var namespaceBig, namespaceSmall []model.AllPkgTreeNamespacesPackageNamespace

	var namesBig, namesSmall []model.AllPkgTreeNamespacesPackageNamespaceNamesPackageName
	var versionBig, versionSmall []model.AllPkgTreeNamespacesPackageNamespaceNamesPackageNameVersionsPackageVersion
	var qualifierBig, qualifierSmall []model.AllPkgTreeNamespacesPackageNamespaceNamesPackageNameVersionsPackageVersionQualifiersPackageQualifier

	diffedNode := Node{}

	switch nodeOne.NodeType {

	case "Package":
		diffedNode.NodeType = "Package"

		nOne := nodeOne.Pkg

		nTwo := nodeTwo.Pkg

		if nodeOne.ID == nodeTwo.ID {
			return diffedNode, []string{}, nil
		}

		if nOne.Type != nTwo.Type {
			diffs = append(diffs, "Type: "+nOne.Type+" != "+nTwo.Type)
			diffedNode.Pkg.Type = ComputeStringDiffs(dmp, nOne.Type, nTwo.Type)
		}

		sort.Sort(packageNameSpaces(nOne.Namespaces))
		sort.Sort(packageNameSpaces(nTwo.Namespaces))

		if len(nTwo.Namespaces) > len(nOne.Namespaces) {
			namespaceBig = nTwo.Namespaces
			namespaceSmall = nOne.Namespaces
		} else if len(nTwo.Namespaces) < len(nOne.Namespaces) {
			namespaceBig = nOne.Namespaces
			namespaceSmall = nTwo.Namespaces
		} else {
			namespaceBig = nTwo.Namespaces
			namespaceSmall = nOne.Namespaces
		}

		diffedNode.Pkg.Namespaces = namespaceSmall

		// Compare namespaces
		for i, namespace1 := range namespaceBig {
			if i >= len(namespaceSmall) {

				diffs = append(diffs, fmt.Sprintf("Namespace %s not present", namespace1.Namespace))
				diffedNode.Pkg.Namespaces = append(diffedNode.Pkg.Namespaces, DiffMissingNamespace(dmp, namespace1))
				continue
			}
			namespace2 := namespaceSmall[i]

			sort.Sort(packageNameSpacesNames(namespace1.Names))
			sort.Sort(packageNameSpacesNames(namespace2.Names))

			// Compare namespace fields
			if namespace1.Namespace != namespace2.Namespace {
				diffs = append(diffs, fmt.Sprintf("Namespace %s != %s", namespace1.Namespace, namespace2.Namespace))
				diffedNode.Pkg.Namespaces[i].Namespace = ComputeStringDiffs(dmp, namespace1.Namespace, namespace2.Namespace)
			}

			if len(namespace1.Names) > len(namespace2.Names) {
				namesBig = namespace1.Names
				namesSmall = namespace2.Names
			} else if len(namespace1.Names) < len(namespace2.Names) {
				namesBig = namespace2.Names
				namesSmall = namespace1.Names
			} else {
				namesBig = namespace1.Names
				namesSmall = namespace2.Names
			}

			diffedNode.Pkg.Namespaces[i].Names = namesSmall

			// Compare names
			for j, name1 := range namesBig {

				if j >= len(namesSmall) {
					diffs = append(diffs, fmt.Sprintf("Name %s not present in namespace %s", name1.Name, namespace1.Namespace))
					diffedNode.Pkg.Namespaces[i].Names = append(diffedNode.Pkg.Namespaces[i].Names, DiffMissingName(dmp, name1))
					continue
				}

				name2 := namesSmall[j]

				sort.Sort(packageNameSpacesNamesVersions(name1.Versions))
				sort.Sort(packageNameSpacesNamesVersions(name2.Versions))

				// Compare name fields
				if name1.Name != name2.Name {
					diffs = append(diffs, fmt.Sprintf("Name %s != %s in Namespace %s", name1.Name, name2.Name, namespace1.Namespace))
					diffedNode.Pkg.Namespaces[i].Names[j].Name = ComputeStringDiffs(dmp, name1.Name, name2.Name)
				}

				if len(name1.Versions) > len(name2.Versions) {
					versionBig = name1.Versions
					versionSmall = name2.Versions
				} else if len(name1.Versions) < len(name2.Versions) {
					versionBig = name2.Versions
					versionSmall = name1.Versions
				} else {
					versionBig = name1.Versions
					versionSmall = name2.Versions
				}

				diffedNode.Pkg.Namespaces[i].Names[j].Versions = versionSmall

				// Compare versions
				for k, version1 := range versionBig {

					if k >= len(versionSmall) {
						diffs = append(diffs, fmt.Sprintf("Version %s not present for name %s in namespace %s,", version1.Version, name1.Name, namespace1.Namespace))
						diffedNode.Pkg.Namespaces[i].Names[j].Versions = append(diffedNode.Pkg.Namespaces[i].Names[j].Versions, DiffMissingVersion(dmp, version1))
						continue
					}

					version2 := versionSmall[k]
					sort.Sort(packageNameSpacesNamesVersionsQualifiers(version1.Qualifiers))
					sort.Sort(packageNameSpacesNamesVersionsQualifiers(version2.Qualifiers))

					if version1.Version != version2.Version {
						diffs = append(diffs, fmt.Sprintf("Version %s != %s for name %s in namespace %s", version1.Version, version2.Version, name1.Name, namespace1.Namespace))
						diffedNode.Pkg.Namespaces[i].Names[j].Versions[k].Version = ComputeStringDiffs(dmp, version1.Version, version2.Version)
					}

					if version1.Subpath != version2.Subpath {
						diffs = append(diffs, fmt.Sprintf("Subpath %s != %s for version %s for name %s in namespace %s", version1.Subpath, version2.Subpath, version1.Version, name1.Name, namespace1.Namespace))
						diffedNode.Pkg.Namespaces[i].Names[j].Versions[k].Subpath = ComputeStringDiffs(dmp, version1.Subpath, version2.Subpath)
					}

					if len(version1.Qualifiers) > len(version2.Qualifiers) {
						qualifierBig = version1.Qualifiers
						qualifierSmall = version2.Qualifiers
					} else if len(version1.Qualifiers) < len(version2.Qualifiers) {
						qualifierBig = version2.Qualifiers
						qualifierSmall = version1.Qualifiers
					} else {
						qualifierBig = version1.Qualifiers
						qualifierSmall = version2.Qualifiers
					}

					diffedNode.Pkg.Namespaces[i].Names[j].Versions[k].Qualifiers = qualifierSmall

					for l, qualifier1 := range qualifierBig {

						if l >= len(qualifierSmall) {
							diffs = append(diffs, fmt.Sprintf("Qualifier %s:%s not present for version %s in name %s in namespace %s,", qualifier1.Key, qualifier1.Value, version1.Version, name1.Name, namespace1.Namespace))
							diffedNode.Pkg.Namespaces[i].Names[j].Versions[k].Qualifiers = append(diffedNode.Pkg.Namespaces[i].Names[j].Versions[k].Qualifiers, DiffMissingQualifier(dmp, qualifier1))
							continue
						}

						qualifier2 := qualifierSmall[l]

						if qualifier2.Key != qualifier1.Key {
							diffs = append(diffs, fmt.Sprintf("Qualifier key unequal for version %s in name %s in namespace %s:  %s:%s | %s:%s", version1.Version, name1.Name, namespace1.Namespace, qualifier1.Key, qualifier1.Value, qualifier2.Key, qualifier2.Value))
							diffedNode.Pkg.Namespaces[i].Names[j].Versions[k].Qualifiers[l].Key = ComputeStringDiffs(dmp, qualifier1.Key, qualifier2.Key)
						}

						if qualifier1.Value != qualifier2.Value {
							diffs = append(diffs, fmt.Sprintf("Qualifier value unequal for version %s in name %s in namespace %s:  %s:%s | %s:%s", version1.Version, name1.Name, namespace1.Namespace, qualifier1.Key, qualifier1.Value, qualifier2.Key, qualifier2.Value))
							diffedNode.Pkg.Namespaces[i].Names[j].Versions[k].Qualifiers[l].Value = ComputeStringDiffs(dmp, qualifier1.Value, qualifier2.Value)
						}
					}
				}
			}
		}
	case "DependencyPackage":

		diffedNode.NodeType = "DependencyPackage"
		nOne := nodeOne.DepPkg

		nTwo := nodeTwo.DepPkg

		if nodeOne.ID == nodeTwo.ID {
			return diffedNode, []string{}, nil
		}

		if nOne.Type != nTwo.Type {
			diffs = append(diffs, "Type: "+nOne.Type+" != "+nTwo.Type)
			diffedNode.DepPkg.Type = ComputeStringDiffs(dmp, nOne.Type, nTwo.Type)
		}

		sort.Sort(packageNameSpaces(nOne.Namespaces))
		sort.Sort(packageNameSpaces(nTwo.Namespaces))

		if len(nTwo.Namespaces) > len(nOne.Namespaces) {
			namespaceBig = nTwo.Namespaces
			namespaceSmall = nOne.Namespaces
		} else if len(nTwo.Namespaces) < len(nOne.Namespaces) {
			namespaceBig = nOne.Namespaces
			namespaceSmall = nTwo.Namespaces
		} else {
			namespaceBig = nTwo.Namespaces
			namespaceSmall = nOne.Namespaces
		}

		diffedNode.DepPkg.Namespaces = namespaceSmall

		// Compare namespaces
		for i, namespace1 := range namespaceBig {
			if i >= len(namespaceSmall) {
				diffs = append(diffs, fmt.Sprintf("Namespace %s not present", namespace1.Namespace))
				diffedNode.DepPkg.Namespaces = append(diffedNode.DepPkg.Namespaces, DiffMissingNamespace(dmp, namespace1))
				continue
			}
			namespace2 := namespaceSmall[i]

			sort.Sort(packageNameSpacesNames(namespace1.Names))
			sort.Sort(packageNameSpacesNames(namespace2.Names))

			// Compare namespace fields
			if namespace1.Namespace != namespace2.Namespace {
				diffs = append(diffs, fmt.Sprintf("Namespace %s != %s", namespace1.Namespace, namespace2.Namespace))
				diffedNode.DepPkg.Namespaces[i].Namespace = ComputeStringDiffs(dmp, namespace1.Namespace, namespace2.Namespace)
			}

			if len(namespace1.Names) > len(namespace2.Names) {
				namesBig = namespace1.Names
				namesSmall = namespace2.Names
			} else if len(namespace1.Names) < len(namespace2.Names) {
				namesBig = namespace2.Names
				namesSmall = namespace1.Names
			} else {
				namesBig = namespace1.Names
				namesSmall = namespace2.Names
			}

			diffedNode.DepPkg.Namespaces[i].Names = namesSmall

			// Compare names
			for j, name1 := range namesBig {

				if j >= len(namesSmall) {
					diffs = append(diffs, fmt.Sprintf("Name %s not present in namespace %s", name1.Name, namespace1.Namespace))
					diffedNode.DepPkg.Namespaces[i].Names = append(diffedNode.DepPkg.Namespaces[i].Names, DiffMissingName(dmp, name1))
					continue
				}
				name2 := namesSmall[j]

				sort.Sort(packageNameSpacesNamesVersions(name1.Versions))
				sort.Sort(packageNameSpacesNamesVersions(name2.Versions))

				// Compare name fields
				if name1.Name != name2.Name {
					diffs = append(diffs, fmt.Sprintf("Name %s != %s in Namespace %s", name1.Name, name2.Name, namespace1.Namespace))
					diffedNode.DepPkg.Namespaces[i].Names[j].Name = ComputeStringDiffs(dmp, name1.Name, name2.Name)
				}

				if len(name1.Versions) > len(name2.Versions) {
					versionBig = name1.Versions
					versionSmall = name2.Versions
				} else if len(name1.Versions) < len(name2.Versions) {
					versionBig = name2.Versions
					versionSmall = name1.Versions
				} else {
					versionBig = name1.Versions
					versionSmall = name2.Versions
				}

				diffedNode.DepPkg.Namespaces[i].Names[j].Versions = versionSmall

				// Compare versions
				for k, version1 := range versionBig {
					if k >= len(versionSmall) {
						diffs = append(diffs, fmt.Sprintf("Version %s not present for name %s in namespace %s,", version1.Version, name1.Name, namespace1.Namespace))
						diffedNode.DepPkg.Namespaces[i].Names[j].Versions = append(diffedNode.DepPkg.Namespaces[i].Names[j].Versions, DiffMissingVersion(dmp, version1))
						continue
					}

					version2 := versionSmall[k]
					sort.Sort(packageNameSpacesNamesVersionsQualifiers(version1.Qualifiers))
					sort.Sort(packageNameSpacesNamesVersionsQualifiers(version2.Qualifiers))

					if version1.Version != version2.Version {
						diffs = append(diffs, fmt.Sprintf("Version %s != %s for name %s in namespace %s", version1.Version, version2.Version, name1.Name, namespace1.Namespace))
						diffedNode.DepPkg.Namespaces[i].Names[j].Versions[k].Version = ComputeStringDiffs(dmp, version1.Version, version2.Version)
					}

					if version1.Subpath != version2.Subpath {
						diffs = append(diffs, fmt.Sprintf("Subpath %s != %s for version %s for name %s in namespace %s", version1.Subpath, version2.Subpath, version1.Version, name1.Name, namespace1.Namespace))
						diffedNode.DepPkg.Namespaces[i].Names[j].Versions[k].Subpath = ComputeStringDiffs(dmp, version1.Subpath, version2.Subpath)
					}

					if len(version1.Qualifiers) > len(version2.Qualifiers) {
						qualifierBig = version1.Qualifiers
						qualifierSmall = version2.Qualifiers
					} else if len(version1.Qualifiers) < len(version2.Qualifiers) {
						qualifierBig = version2.Qualifiers
						qualifierSmall = version1.Qualifiers
					} else {
						qualifierBig = version1.Qualifiers
						qualifierSmall = version2.Qualifiers
					}

					diffedNode.DepPkg.Namespaces[i].Names[j].Versions[k].Qualifiers = qualifierSmall

					for l, qualifier1 := range qualifierBig {
						if l >= len(qualifierSmall) {
							diffs = append(diffs, fmt.Sprintf("Qualifier %s:%s not present for version %s in name %s in namespace %s,", qualifier1.Key, qualifier1.Value, version1.Version, name1.Name, namespace1.Namespace))
							diffedNode.DepPkg.Namespaces[i].Names[j].Versions[k].Qualifiers = append(diffedNode.DepPkg.Namespaces[i].Names[j].Versions[k].Qualifiers, DiffMissingQualifier(dmp, qualifier1))
							continue
						}

						qualifier2 := qualifierSmall[l]

						if qualifier2.Key != qualifier1.Key {
							diffs = append(diffs, fmt.Sprintf("Qualifier key unequal for version %s in name %s in namespace %s:  %s:%s | %s:%s", version1.Version, name1.Name, namespace1.Namespace, qualifier1.Key, qualifier1.Value, qualifier2.Key, qualifier2.Value))
							diffedNode.DepPkg.Namespaces[i].Names[j].Versions[k].Qualifiers[l].Key = ComputeStringDiffs(dmp, qualifier1.Key, qualifier2.Key)
						}

						if qualifier1.Value != qualifier2.Value {
							diffs = append(diffs, fmt.Sprintf("Qualifier value unequal for version %s in name %s in namespace %s:  %s:%s | %s:%s", version1.Version, name1.Name, namespace1.Namespace, qualifier1.Key, qualifier1.Value, qualifier2.Key, qualifier2.Value))
							diffedNode.DepPkg.Namespaces[i].Names[j].Versions[k].Qualifiers[l].Value = ComputeStringDiffs(dmp, qualifier1.Value, qualifier2.Value)
						}
					}
				}
			}
		}
	}
	return diffedNode, diffs, nil
}
func CompareTwoPaths(dmp *diffmatchpatch.DiffMatchPatch, analysisListOne, analysisListTwo []*Node) ([]Node, [][]string, int, error) {
	var longerPath, shorterPath []*Node

	if len(analysisListOne) > len(analysisListTwo) {
		longerPath = analysisListOne
		shorterPath = analysisListTwo
	} else {
		longerPath = analysisListTwo
		shorterPath = analysisListOne
	}

	pathDiff := make([][]string, len(longerPath))
	nodesDiff := make([]Node, len(longerPath))
	var diffCount int

	var wg sync.WaitGroup
	var mu sync.Mutex
	errChan := make(chan error, len(longerPath)) // Buffer channel to hold errors

	for i, node := range longerPath {
		wg.Add(1)
		go func(i int, node *Node) {
			defer wg.Done()

			var diffs []string
			var diffNode Node
			var err error

			if i >= len(shorterPath) {
				dumnode := &Node{}
				if node.NodeType == "Package" {
					dumnode.NodeType = "Package"
					dumnode.Pkg = model.AllIsDependencyTreePackage{}
				} else if node.NodeType == "DependencyPackage" {
					dumnode.NodeType = "DependencyPackage"
					dumnode.DepPkg = model.AllIsDependencyTreeDependencyPackage{}
				}

				diffNode, diffs, err = compareNodes(dmp, *node, *dumnode)
			} else {
				diffNode, diffs, err = compareNodes(dmp, *node, *shorterPath[i])
			}

			if err != nil {
				errChan <- err
				return
			}

			mu.Lock()
			pathDiff[i] = diffs
			nodesDiff[i] = diffNode
			diffCount += len(diffs)
			mu.Unlock()
		}(i, node)
	}

	wg.Wait()
	close(errChan) // Close the channel after all goroutines are done

	// Check for errors
	if len(errChan) != 0 {
		return nodesDiff, pathDiff, 0, fmt.Errorf("could not diff node")
	}

	return nodesDiff, pathDiff, diffCount, nil
}

func CompareAllPaths(listOne, listTwo [][]*Node) (DiffResult, error) {

	var small, big [][]*Node
	if len(listOne) > len(listTwo) {
		small = listTwo
		big = listOne
	} else if len(listTwo) > len(listOne) {
		small = listOne
		big = listTwo
	} else {
		small = listTwo
		big = listOne
	}

	var pathResults []DiffedPath
	nodeResults := make(map[string]DiffedNodePair)

	used := make(map[int]bool)

	for _, pathOne := range small {

		var pathDiff DiffedPath

		pathDiff.PathOne = pathOne
		min := math.MaxInt32
		var index int
		diffIndices := []EqualDifferencesPaths{}

		for i, pathTwo := range big {
			_, ok := used[i]
			if ok {
				continue
			}
			dmp := diffmatchpatch.New()

			nodeDiffs, diffs, diffNum, err := CompareTwoPaths(dmp, pathOne, pathTwo)

			if err != nil {
				return DiffResult{}, fmt.Errorf("error comparing paths %v", err.Error())
			}

			if diffNum < min {
				pathDiff.PathTwo = pathTwo
				min = diffNum
				pathDiff.Diffs = diffs
				pathDiff.NodeDiffs = nodeDiffs
				index = i
				diffIndices = []EqualDifferencesPaths{{Diffs: diffs, Path: pathTwo, Index: i}}
			} else if diffNum == min {
				diffIndices = append(diffIndices, EqualDifferencesPaths{Diffs: diffs, Path: pathTwo, Index: i})
			}
		}

		if len(diffIndices) == 1 {
			used[index] = true
		}

		count := 0
		seenNodeIndex := -1

		//find if there is only one node causing the paths to differ. If yes, then mark it in the seen map.
		for k, list := range pathDiff.Diffs {
			if len(list) > 0 {
				count++
				seenNodeIndex = k
			}
		}

		if count == 1 {
			key := ""
			if _, exists := nodeResults[pathDiff.PathOne[seenNodeIndex].ID+pathDiff.PathTwo[seenNodeIndex].ID]; exists {
				key = pathDiff.PathOne[seenNodeIndex].ID + pathDiff.PathTwo[seenNodeIndex].ID
				nodeResults[key] = DiffedNodePair{NodeOne: pathDiff.PathOne[seenNodeIndex], NodeTwo: pathDiff.PathTwo[seenNodeIndex], Count: nodeResults[key].Count + 1}

			} else if _, exists := nodeResults[pathDiff.PathTwo[seenNodeIndex].ID+pathDiff.PathOne[seenNodeIndex].ID]; exists {
				key = pathDiff.PathTwo[seenNodeIndex].ID + pathDiff.PathOne[seenNodeIndex].ID
				nodeResults[key] = DiffedNodePair{NodeOne: pathDiff.PathOne[seenNodeIndex], NodeTwo: pathDiff.PathTwo[seenNodeIndex], Count: nodeResults[key].Count + 1}

			} else {
				key = pathDiff.PathTwo[seenNodeIndex].ID + pathDiff.PathOne[seenNodeIndex].ID
				nodeResults[key] = DiffedNodePair{NodeOne: pathDiff.PathOne[seenNodeIndex], NodeTwo: pathDiff.PathTwo[seenNodeIndex], Count: 1}
			}
			continue
		}

		pathResults = append(pathResults, pathDiff)
	}

	for i, val := range big {
		_, ok := used[i]
		if !ok {

			//diff each missing path and append to result
			var missingPath []Node
			for _, node := range val {
				dumnode := &Node{}
				if node.NodeType == "Package" {
					dumnode.NodeType = "Package"
					dumnode.Pkg = model.AllIsDependencyTreePackage{}
				} else if node.NodeType == "DependencyPackage" {
					dumnode.NodeType = "DependencyPackage"
					dumnode.DepPkg = model.AllIsDependencyTreeDependencyPackage{}
				}
				dmp := diffmatchpatch.New()
				diffNode, _, err := compareNodes(dmp, *node, *dumnode)
				if err != nil {
					return DiffResult{}, fmt.Errorf("error comparing nodes %v", err.Error())
				}
				missingPath = append(missingPath, diffNode)

			}
			pathResults = append(pathResults, DiffedPath{PathOne: val, NodeDiffs: missingPath})
		}
	}
	return DiffResult{Paths: pathResults, Nodes: nodeResults}, nil
}
