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

// TODO: add tests
func ToposortFromBfsNodeMap(ctx context.Context, gqlClient graphql.Client, nodeMap map[string]BfsNode) (map[int][]string, []string, error) {
	frontiers := make(map[int][]string)
	parentsMap, infoNodes := copyParents(nodeMap)
	frontierLevel := 0
	numNodes := 0
	totalNodes := len(parentsMap)

	for numNodes < totalNodes {
		foundIDs := make(map[string]bool)
		for id, parentsList := range parentsMap {
			if len(parentsList) == 0 || (parentsList[0] == "" && len(parentsList) == 1) {
				frontiers[frontierLevel] = append(frontiers[frontierLevel], id)
				foundIDs[id] = true
				numNodes++
			}
		}

		if len(foundIDs) == 0 {
			return frontiers, infoNodes, fmt.Errorf("error: cycle detected")
		}

		for id := range foundIDs {
			delete(parentsMap, id)
		}

		for id, parentsList := range parentsMap {
			newParentsList := []string{}
			for _, parentID := range parentsList {
				if !foundIDs[parentID] {
					newParentsList = append(newParentsList, parentID)
				}
			}

			parentsMap[id] = newParentsList
		}
		frontierLevel++
	}

	return frontiers, infoNodes, nil
}

func copyParents(inputMap map[string]BfsNode) (map[string][]string, []string) {
	retMap := map[string][]string{}
	var infoNodes []string
	for key, value := range inputMap {
		if !value.NotInBlastRadius {
			retMap[key] = append(retMap[key], value.Parents...)
		} else {
			infoNodes = append(infoNodes, key)
		}
	}
	return retMap, infoNodes
}
