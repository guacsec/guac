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

func ToposortFromBfsNodeMap(nodeMap map[string]BfsNode) (map[int][]BfsNode, error) {
	// Step 1: make a copy of the inputted nodeMap to modify the old parents values without losing the info, and remove info nodes
	// Step 2: Loop until the numNodes discovered is >= the numNodes in the new nodeMap
	// Step 3: Loop through each node in the new nodeMap and find nodes with len(parents) == 0
	// Step 4: Add these nodes with len(parents) == 0 to the return map
	// Step 5: Loop through each node in the new nodeMap (not nested in prev loop) and remove the latest parents found from their parents list
	// Step 6: If no nodes have len(parents) == 0 then cycle is detected (ERROR)
	// Step 7: Increment outermost loop by num of nodes found

	return nil, fmt.Errorf("Unimplemented")
}
