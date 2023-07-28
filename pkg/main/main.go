package main

import (
	"fmt"

	g "github.com/guacsec/guac/pkg/guacanalytics"
)

func main() {
	nodeMap := make(map[string]g.BfsNode)

	nodeMap["10"] = g.BfsNode{}
	nodeMap["11"] = g.BfsNode{
		Parents: []string{"10"},
	}

	ret, err := g.ToposortFromBfsNodeMap(nodeMap)

	if err != nil {
		fmt.Printf("%s\n", err)
	}

	for key, value := range ret {
		for _, v := range value {
			fmt.Printf("%d : %s \n", key, v)
		}
	}
}
