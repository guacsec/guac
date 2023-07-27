// Copyright 2023 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package guacanalytics

import (
	"fmt"
)

// TODO: add tests
func ToposortFromBfsNodeMap(nodeMap map[string]BfsNode) (map[int][]BfsNode, error) {
	frontiers := make(map[int][]BfsNode)
	parentsMap := copyParents(nodeMap)
	frontierLevel := 0

	for numNodes := 0; numNodes <= len(parentsMap); numNodes++ {
		var foundIDs []string
		for id, parentsList := range parentsMap {
			if len(parentsList) == 0 {
				frontiers[frontierLevel] = append(frontiers[frontierLevel], nodeMap[id])
				foundIDs = append(foundIDs, id)
				numNodes++
			}
		}

		if len(foundIDs) == 0 {
			return frontiers, fmt.Errorf("Error: cycle detected")
		}

		for id, parentsList := range parentsMap {
			for index, parentID := range parentsList {
				for _, foundID := range foundIDs {
					if parentID == foundID {
						parentsMap[id] = append(parentsList[:index], parentsList[index+1:]...)
					}
				}
			}
		}
		frontierLevel++
	}

	return frontiers, nil
}

func copyParents(inputMap map[string]BfsNode) map[string][]string {
	retMap := map[string][]string{}
	for key, value := range inputMap {
		if !value.NotInBlastRadius {
			retMap[key] = append(retMap[key], value.Parents...)
		}
	}
	return retMap
}
