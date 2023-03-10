package testing

import (
	"fmt"
	"reflect"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// For each software tree we define recursive maps to represent the softrware tries
// where the key of the trie is the serialization of the content of the trie node.
type pkgT map[string]pkgNamespaceT
type pkgNamespaceT map[string]pkgNameT
type pkgNameT map[string]*pkgVersionT
type pkgVersionT []*model.PackageVersion

func (c *demoClient) pkgId(v *model.Package) nodeId {
	typ := v.Type
	ns := v.Namespaces[0]
	name := ns.Names[0]

	pkgNameNode := c.pkgT[typ][ns.Namespace][name.Name]
	if len(name.Versions) == 0 {
		fmt.Println("finding:", typ, ns.Namespace, name.Name)
		return pkgNameNode
	}

	version := name.Versions[0]
	fmt.Println("finding:", typ, ns.Namespace, name.Name, version)
	for _, n := range *pkgNameNode {
		if reflect.DeepEqual(version, n) {
			return n
		}
	}

	panic(fmt.Sprintf("couldn't identify pkgId: %+v", v))
}

// A function will be used to provide a pointer to the node on the trie
type nodeId any

// The backEdges are defined by pointers from software tree nodes to a set of
// evidence tree structs
type backEdges map[nodeId]*evidenceTrees

// evidenceTreeEdges is a struct that contains a list of edges from a software
// tree node
type evidenceTrees struct {
	isDependency []*model.IsDependency // this can be later indexed if necessary
}

// Edge traversal from SW tree to EV tree would be an index from a software node into
// the edges map
// e.g. isDepEdges := edges[nodeId].isDepedency
