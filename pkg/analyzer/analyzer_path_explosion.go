package analyzer

import (
	"fmt"

	"github.com/dominikbraun/graph"
)

func GetLeafNodes(adjMap map[string]map[string]graph.Edge[string]) map[string]bool {
	leafNodes := make(map[string]bool)
	for i, nodeMap := range adjMap {
		if len(nodeMap) == 0 {
			leafNodes[i] = true
		}
	}
	return leafNodes
}

func GetPredecessor(adjMap map[string]map[string]graph.Edge[string], id string) map[string]bool {
	predecessors := make(map[string]bool)
	for i, nodeMap := range adjMap {
		_, ok := nodeMap[id]
		if ok {
			predecessors[i] = true
		}
	}
	return predecessors
}

func recursiveSubgraphIncrease(adjMapOne, adjMapTwo map[string]map[string]graph.Edge[string], currentNodeId string) []string {
	predecessorsOne := GetPredecessor(adjMapOne, currentNodeId)
	predecessorsTwo := GetPredecessor(adjMapTwo, currentNodeId)
	nodesToRemove := []string{}

	if len(predecessorsOne) == 1 && len(predecessorsTwo) == 1 {
		nodesToRemove = append(nodesToRemove, currentNodeId)
	}

	if len(predecessorsOne) != len(predecessorsTwo) {
		//cannot proceed ahead with recursion
		return nodesToRemove
	}

	predecessorsToRemove := []string{}

	//now check all nodes are the same and start recursion
	for val := range predecessorsOne {
		_, ok := predecessorsTwo[val]
		if !ok {
			return nodesToRemove
		}
		if val == "HasSBOM" {
			continue
		}
		predecessorsToRemove = append(predecessorsToRemove, recursiveSubgraphIncrease(adjMapOne, adjMapTwo, val)...)
	}

	//add currentNode predecessors
	if len(predecessorsOne) != 1 && len(predecessorsToRemove) != 0 {
		for predecessor := range predecessorsOne {
			nodesToRemove = append(nodesToRemove, predecessor)
		}
	}

	nodesToRemove = append(nodesToRemove, predecessorsToRemove...)
	return nodesToRemove
}

func CompressGraphs(g1, g2 graph.Graph[string, *Node]) (graph.Graph[string, *Node], graph.Graph[string, *Node], error) {
	gOneAdjacencyMap, errOne := g1.AdjacencyMap()

	gTwoAdjacencyMap, errTwo := g2.AdjacencyMap()

	if errOne != nil || errTwo != nil {
		return g1, g2, fmt.Errorf("error getting graph adjacency list")
	}

	gOneLeafNodes := GetLeafNodes(gOneAdjacencyMap)
	gTwoLeafNodes := GetLeafNodes(gTwoAdjacencyMap)

	var small, big map[string]bool
	var smallMap, bigMap map[string]map[string]graph.Edge[string]
	var nodesToRemove []string
	if len(gOneLeafNodes) < len(gTwoLeafNodes) {
		small = gOneLeafNodes
		big = gTwoLeafNodes
		smallMap = gOneAdjacencyMap
		bigMap = gTwoAdjacencyMap
	} else if len(gOneLeafNodes) > len(gTwoLeafNodes) {
		big = gOneLeafNodes
		small = gTwoLeafNodes

		bigMap = gOneAdjacencyMap
		smallMap = gTwoAdjacencyMap
	} else {
		small = gOneLeafNodes
		big = gTwoLeafNodes

		smallMap = gOneAdjacencyMap
		bigMap = gTwoAdjacencyMap
	}

	for smallId := range small {
		_, ok := big[smallId]
		if ok {
			//go upwards
			nodesToRemove = append(nodesToRemove, recursiveSubgraphIncrease(smallMap, bigMap, smallId)...)
		}
	}

	//REMOVE OUTGOING EDGES & REMOVE INCOMING EDGES & REMOVE NODES
	for _, val := range nodesToRemove {

		nodeMapOne, ok := gOneAdjacencyMap[val]
		if !ok {
			return g1, g2, fmt.Errorf("node to delete not found in nodeMapOne")
		}

		nodeMapTwo, ok := gTwoAdjacencyMap[val]
		if !ok {
			return g1, g2, fmt.Errorf("node to delete not found in nodeMapTwo")
		}

		//delete incoming edges to node one

		for _, nodeMapOne := range gOneAdjacencyMap {

			if len(nodeMapOne) == 0 {
				continue
			}

			for to, edge := range nodeMapOne {
				if to == val {
					errOne := g1.RemoveEdge(edge.Source, edge.Target)
					if errOne != nil {
						return g1, g2, fmt.Errorf("(in1) unable to delete edge from graph %v", errOne)
					}
				}
			}
		}

		//delete incoming edges to node two
		for _, nodeMapTwo := range gTwoAdjacencyMap {

			if len(nodeMapTwo) == 0 {
				continue
			}

			for to, edge := range nodeMapTwo {
				if to == val {
					errTwo := g2.RemoveEdge(edge.Source, edge.Target)
					if errTwo != nil {
						return g1, g2, fmt.Errorf("(in2) unable to delete edge from graph %v", errTwo)
					}
				}
			}
		}

		//delete outgoing nodes from graph one
		if len(nodeMapOne) != 0 {
			for _, edge := range nodeMapOne {
				errOne := g1.RemoveEdge(edge.Source, edge.Target)
				if errOne != nil {
					return g1, g2, fmt.Errorf("(out1) unable to delete edge from graph %v", errOne)
				}
			}
		}

		//delete outgoing nodes from graph two
		if len(nodeMapTwo) != 0 {
			for _, edge := range nodeMapTwo {
				errTwo := g2.RemoveEdge(edge.Source, edge.Target)
				if errTwo != nil {
					return g1, g2, fmt.Errorf("(out2) unable to delete edge from graph %v", errTwo)
				}
			}
		}

		errOne := g1.RemoveVertex(val)
		errTwo := g2.RemoveVertex(val)

		if errOne != nil || errTwo != nil {
			return g1, g2, fmt.Errorf("unable to delete node from graph %v %v", errOne, errTwo)
		}
	}
	return g1, g2, nil
}
