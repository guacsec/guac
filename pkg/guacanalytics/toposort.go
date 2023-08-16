//
// Copyright 2023 The GUAC Authors.
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

package guacanalytics

import (
	"context"
	"fmt"

	"github.com/Khan/genqlient/graphql"
)

// TopoSortFromBfsNodeMap sorts the nodes such that it returns a map of level -> list of nodeIDs at that level
func TopoSortFromBfsNodeMap(ctx context.Context, gqlClient graphql.Client, nodeMap map[string]BfsNode) (map[int][]string, []string, error) {
	sortedNodes := make(map[int][]string) // map of level -> list of nodeIDs at that level
	parentsMap, childrensMap, infoNodes := copyParents(nodeMap)
	// parentsMap: map of nodeID (child) -> the struct parent which contains a list of parents in the form of a map
	// childrensMap: map of nodeID (parent) -> list of children in the form of an array
	bfsLevel := 0
	numNodes := 0
	totalNodes := len(parentsMap)

	for numNodes < totalNodes {
		foundIDs := make(map[string]bool)
		for id, p := range parentsMap {
			if p.parents != nil && len(p.parents) == 0 { // if this node has no parents, it is a root node
				sortedNodes[bfsLevel] = append(sortedNodes[bfsLevel], id)
				numNodes++
				foundIDs[id] = true
			}
		}

		for id := range foundIDs {
			delete(parentsMap, id)                     // remove this node from the map of parents
			for _, childID := range childrensMap[id] { // loop through all the children of this node
				delete(parentsMap[childID].parents, id) // remove this node from the map of parents of the child
			}
		}

		if len(foundIDs) == 0 {
			// TODO: print out offending cycle
			return sortedNodes, infoNodes, fmt.Errorf("error: cycle detected")
		}

		bfsLevel++
	}

	return sortedNodes, infoNodes, nil
}

func copyParents(inputMap map[string]BfsNode) (map[string]parent, map[string][]string, []string) {
	parentsMap := map[string]parent{}    // map of nodeID (child) -> map of the childs parents
	childrenMap := map[string][]string{} // map of nodeID (parent) -> list of the parents children
	var infoNodes []string
	for key, value := range inputMap {
		if !value.NotInBlastRadius {
			if _, ok := parentsMap[key]; !ok {
				parentsMap[key] = parent{make(map[string]bool)}
			}

			for _, parent := range value.Parents {
				parentsMap[key].parents[parent] = true
				childrenMap[parent] = append(childrenMap[parent], key)
			}
		} else {
			infoNodes = append(infoNodes, key)
		}
	}

	return parentsMap, childrenMap, infoNodes
}

type parent struct {
	parents map[string]bool // Consider the map[string]bool as a set, the value doesn't matter just the key
}
