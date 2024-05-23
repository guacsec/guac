package server

import (
	"context"
	"fmt"

	"github.com/Khan/genqlient/graphql"
	gql "github.com/guacsec/guac/pkg/assembler/clients/generated"
	assembler_helpers "github.com/guacsec/guac/pkg/assembler/helpers"
	gen "github.com/guacsec/guac/pkg/guacrest/generated"
	"github.com/guacsec/guac/pkg/guacrest/helpers"
	"github.com/guacsec/guac/pkg/guacrest/pagination"
	"github.com/guacsec/guac/pkg/logging"
	"golang.org/x/exp/maps"
)

// node is implemented by all graphQL client types
type node interface {
	GetId() string
}

// edgeGen defines the edges used by the transitive dependencies graph traversal.
type edgeGen interface {
	// getDirectDependencies returns the nouns that are direct dependencies of the input noun.
	getDirectDependencies(ctx context.Context, v node) ([]node, error)

	// getEquivalentNodes returns the nouns that are considered equivalent to the input noun.
	getEquivalentNodes(ctx context.Context, v node) ([]node, error)
}

// byDigest is an edgeGen that observes relationships between nouns when they are
// linked by digest.
//
// The dependency edges are:
// - artifact -> sbom -> package
// - artifact -> sbom -> artifact
// - artifact -> slsa -> artifact
//
// And the equivalence edges are:
// - artifact -> IsOccurrence -> package
// - artifact -> HashEquals -> artifact
//
// byDigest lazily generates edges using calls to the GraphQL server, instead
// of precomputing the graph.
type byDigest struct {
	gqlClient graphql.Client
}

func newByDigest(gqlClient graphql.Client) byDigest {
	return byDigest{gqlClient: gqlClient}
}

// byName is a edgeGen that respects all relationships between nouns, whether they
// are linked by hash or by name. It is useful when SBOMs don't provide the digest
// of the subject.
//
// It implements all edges defined by byDigest, in addition to the following:
// dependency edges:
// - package -> sbom -> package
// - package -> sbom -> artifact
//
// equivalence edges:
// - package -> IsOccurrence -> artifact
//
// byName lazily generates edges using calls to the GraphQL server, instead of
// precomputing the graph.
type byName struct {
	gqlClient graphql.Client
	bd        byDigest
}

func newByName(gqlClient graphql.Client) byName {
	return byName{gqlClient: gqlClient, bd: newByDigest(gqlClient)}
}

/********* The graph traversal *********/

func getTransitiveDependencies(
	ctx context.Context,
	gqlClient graphql.Client,
	start node,
	edges edgeGen) ([]node, error) {

	// As the queue in this function is essentially a list of IO actions, this
	// function could be optimized by running through the queue and executing
	// all of them concurrently.

	queue := []node{start}
	visited := map[string]node{}

	// maintain the set of nodes are equivalent to the start node, including the start node
	nodesEquivalentToStart := map[node]any{start: struct{}{}}

	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]

		if _, ok := visited[node.GetId()]; ok {
			continue
		}
		visited[node.GetId()] = node

		adjacent, err := edges.getDirectDependencies(ctx, node)
		if err != nil {
			return nil, err
		}
		queue = append(queue, adjacent...)

		adjacent, err = edges.getEquivalentNodes(ctx, node)
		if err != nil {
			return nil, err
		}
		queue = append(queue, adjacent...)

		if _, ok := nodesEquivalentToStart[node]; ok {
			for _, equivalentNode := range adjacent {
				nodesEquivalentToStart[equivalentNode] = struct{}{}
			}
		}
	}

	// Nodes equivalent to the start node are not dependencies
	for node := range nodesEquivalentToStart {
		delete(visited, node.GetId())
	}
	return maps.Values(visited), nil
}

/********* Implementations of the interface *********/

func (eg byDigest) getDirectDependencies(ctx context.Context, v node) ([]node, error) {
	edgesToPredicates := []gql.Edge{
		gql.EdgeArtifactHasSbom,
		gql.EdgeArtifactHasSlsa,
	}
	edgesFromPredicates := []gql.Edge{
		gql.EdgeHasSbomIncludedSoftware,
		gql.EdgeHasSlsaMaterials,
	}
	return neighborsTwoHops(ctx, eg.gqlClient, v, edgesToPredicates, edgesFromPredicates)
}

func (eg byDigest) getEquivalentNodes(ctx context.Context, v node) ([]node, error) {
	edgesToPredicates := []gql.Edge{
		gql.EdgeArtifactIsOccurrence,
		gql.EdgeArtifactHashEqual,
	}
	edgesFromPredicates := []gql.Edge{
		gql.EdgeIsOccurrenceArtifact,
		gql.EdgeIsOccurrencePackage,
		gql.EdgeHashEqualArtifact,
	}
	return neighborsTwoHops(ctx, eg.gqlClient, v, edgesToPredicates, edgesFromPredicates)
}

func (eg byName) getDirectDependencies(ctx context.Context, v node) ([]node, error) {
	edgesToPredicates := []gql.Edge{
		gql.EdgePackageHasSbom,
		gql.EdgeArtifactHasSbom,
		gql.EdgeArtifactHasSlsa,
	}
	edgesFromPredicates := []gql.Edge{
		gql.EdgeHasSbomIncludedSoftware,
		gql.EdgeHasSlsaMaterials,
	}
	return neighborsTwoHops(ctx, eg.gqlClient, v, edgesToPredicates, edgesFromPredicates)
}

func (eg byName) getEquivalentNodes(ctx context.Context, v node) ([]node, error) {
	edgesToPredicates := []gql.Edge{
		gql.EdgePackageIsOccurrence,
		gql.EdgeArtifactIsOccurrence,
		gql.EdgeArtifactHashEqual,
	}
	edgesFromPredicates := []gql.Edge{
		gql.EdgeIsOccurrenceArtifact,
		gql.EdgeIsOccurrencePackage,
		gql.EdgeHashEqualArtifact,
	}
	return neighborsTwoHops(ctx, eg.gqlClient, v, edgesToPredicates, edgesFromPredicates)
}

/********* Graphql helper functions *********/

// neighborsTwoHops calls the GraphQL Neighbors endpoint once with edgesToPredicates, and
// then again on the result with edgesFromPredicates.
func neighborsTwoHops(ctx context.Context, gqlClient graphql.Client, v node,
	edgesToPredicates []gql.Edge, edgesFromPredicates []gql.Edge) ([]node, error) {
	predicates, err := neighbors(ctx, gqlClient, v, edgesToPredicates)
	if err != nil {
		return nil, err
	}

	res := []node{}
	for _, predicate := range predicates {
		nodes, err := neighbors(ctx, gqlClient, predicate, edgesFromPredicates)
		if err != nil {
			return nil, err
		}
		res = append(res, nodes...)
	}
	return res, nil
}

// neighbors calls the GraphQL Neighbors endpoint.
func neighbors(ctx context.Context, gqlClient graphql.Client, v node, edges []gql.Edge) ([]node, error) {
	logger := logging.FromContext(ctx)
	neighborsResponse, err := gql.Neighbors(ctx, gqlClient, v.GetId(), edges)
	if err != nil {
		logger.Errorf("Neighbors query returned err: ", err)
		return nil, helpers.Err502
	}
	if neighborsResponse == nil {
		logger.Errorf("Neighbors query returned nil")
		return nil, helpers.Err500
	}
	return transformWithError(ctx, neighborsResponse.GetNeighbors(), neighborToNode)
}

// Maps a list of As to a list of Bs
func transformWithError[A any, B any](ctx context.Context, lst []A, f func(context.Context, A) (B, error)) ([]B, error) {
	res := []B{}
	for _, x := range lst {
		transformed, err := f(ctx, x)
		if err != nil {
			return nil, err
		}
		res = append(res, transformed)
	}
	return res, nil
}

// Returns the graphQL type that is nested in the neighbors response node. For package tries,
// the leaf version node is returned. Only the types relevant to the retrieveDependecies
// graph traversal are implemented.
func neighborToNode(ctx context.Context, neighborsNode gql.NeighborsNeighborsNode) (node, error) {
	logger := logging.FromContext(ctx)
	switch val := neighborsNode.(type) {
	case *gql.NeighborsNeighborsArtifact:
		if val == nil {
			logger.Errorf("neighbors node is nil")
			return nil, helpers.Err500
		}
		return &val.AllArtifactTree, nil
	case *gql.NeighborsNeighborsPackage:
		if val == nil {
			logger.Errorf("neighbors node is nil")
			return nil, helpers.Err500
		}
		packageVersions := helpers.GetVersionsOfAllPackageTree(val.AllPkgTree)
		if len(packageVersions) > 1 {
			logger.Errorf("NeighborsNeighborsPackage value contains more than one package version node")
			return nil, helpers.Err500
		}

		// this will occur if the neighbors response is a package name node
		if len(packageVersions) == 0 {
			return nil, nil
		}

		return &packageVersions[0], nil
	case *gql.NeighborsNeighborsHasSBOM:
		if val == nil {
			logger.Errorf("neighbors node is nil")
			return nil, helpers.Err500
		}
		return &val.AllHasSBOMTree, nil
	case *gql.NeighborsNeighborsIsOccurrence:
		if val == nil {
			logger.Errorf("neighbors node is nil")
			return nil, helpers.Err500
		}
		return &val.AllIsOccurrencesTree, nil
	case *gql.NeighborsNeighborsHashEqual:
		if val == nil {
			logger.Errorf("neighbors node is nil")
			return nil, helpers.Err500
		}
		return &val.AllHashEqualTree, nil
	case *gql.NeighborsNeighborsHasSLSA:
		if val == nil {
			logger.Errorf("neighbors node is nil")
			return nil, helpers.Err500
		}
		return &val.AllSLSATree, nil
	}
	logger.Errorf("neighborsResponseToNode received an unexpected node type: %T", neighborsNode)
	return nil, helpers.Err500
}

// Maps nodes in the input to purls, ignoring nodes that are not package version
// nodes.
func mapPkgNodesToPurls(ctx context.Context, gqlClient graphql.Client,
	nodes []node) ([]string, error) {
	logger := logging.FromContext(ctx)

	// get the IDs of the package nodes
	pkgIds := []string{}
	for _, node := range nodes {
		if v, ok := node.(*gql.AllPkgTreeNamespacesPackageNamespaceNamesPackageNameVersionsPackageVersion); ok {
			if v == nil {
				logger.Warnf("An gql version node is unexpectedly nil")
				continue
			}
			pkgIds = append(pkgIds, node.GetId())
		}
	}

	// Call Nodes to get the entire package trie for each node
	gqlNodes, err := gql.Nodes(ctx, gqlClient, pkgIds)
	if err != nil {
		logger.Errorf("Nodes query returned err: ", err)
		return nil, helpers.Err502
	}
	if gqlNodes == nil {
		logger.Errorf("The Nodes query returned a nil result.")
		return nil, helpers.Err500
	}
	if len(gqlNodes.GetNodes()) != len(pkgIds) {
		logger.Warnf("GQL query \"nodes\" did not return the expected number of results")
	}

	// map the package tries to purls
	purls := make([]string, 0, len(gqlNodes.GetNodes()))
	for _, gqlNode := range gqlNodes.GetNodes() {
		if v, ok := gqlNode.(*gql.NodesNodesPackage); ok {
			purl := assembler_helpers.AllPkgTreeToPurl(&v.AllPkgTree)
			purls = append(purls, purl)
		} else {
			logger.Warnf("Nodes query returned an unexpected type: %T", *gqlNode.GetTypename())
		}
	}
	return purls, nil
}

/********* The endpoint handler *********/
func (s *DefaultServer) RetrieveDependencies(
	ctx context.Context,
	request gen.RetrieveDependenciesRequestObject,
) (gen.RetrieveDependenciesResponseObject, error) {
	// Find the start node
	var start node
	if request.Params.Purl != nil {
		pkg, err := helpers.FindPackageWithPurl(ctx, s.gqlClient, *request.Params.Purl)
		if err != nil {
			return handleErr(ctx, err), nil
		}
		start = &pkg
	} else if request.Params.Digest != nil {
		artifact, err := helpers.FindArtifactWithDigest(ctx, s.gqlClient, *request.Params.Digest)
		if err != nil {
			return handleErr(ctx, err), nil
		}
		start = &artifact
	} else {
		return gen.RetrieveDependencies400JSONResponse{
			BadRequestJSONResponse: gen.BadRequestJSONResponse{
				Message: "Neither a purl or a digest argument was provided",
			}}, nil
	}

	// Select the edgeGen. The default is byDigest
	var edgeGenerator edgeGen
	cond := request.Params.LinkCondition
	if cond == nil {
		edgeGenerator = newByDigest(s.gqlClient)
	} else if *cond == gen.Name {
		edgeGenerator = newByName(s.gqlClient)
	} else if *cond == gen.Digest {
		edgeGenerator = newByDigest(s.gqlClient)
	} else {
		err := fmt.Errorf("Unrecognized linkCondition: %s", *request.Params.LinkCondition)
		return handleErr(ctx, err), nil
	}

	// Compute the result and map to purls
	deps, err := getTransitiveDependencies(ctx, s.gqlClient, start, edgeGenerator)
	if err != nil {
		return handleErr(ctx, err), nil
	}
	purls, err := mapPkgNodesToPurls(ctx, s.gqlClient, deps)
	if err != nil {
		return handleErr(ctx, err), nil
	}

	page, pageInfo, err := pagination.Paginate(ctx, purls, request.Params.PaginationSpec)
	if err != nil {
		return handleErr(ctx, err), nil
	}
	return gen.RetrieveDependencies200JSONResponse{PurlListJSONResponse: gen.PurlListJSONResponse{
		PurlList:       page,
		PaginationInfo: pageInfo,
	}}, nil
}
