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

package arangodb

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/arangodb/go-driver"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

type edgeMap map[model.Edge]bool

func processUsingOnly(usingOnly []model.Edge) edgeMap {
	m := edgeMap{}
	allowedEdges := usingOnly
	if len(usingOnly) == 0 {
		allowedEdges = model.AllEdge
	}
	for _, edge := range allowedEdges {
		m[edge] = true
	}
	return m
}

func (c *arangoClient) Path(ctx context.Context, startNodeID string, targetNodeID string, maxPathLength int, usingOnly []model.Edge) ([]model.Node, error) {
	values := map[string]any{}
	values["startVertex"] = startNodeID
	values["targetVertex"] = targetNodeID
	values["maxLength"] = maxPathLength

	var sb strings.Builder

	edgeCollectionWriter := func(sb *strings.Builder, i, j int, edgeCollection string) {
		values["edgeCollection"+strconv.Itoa(i)+strconv.Itoa(j)] = edgeCollection
		sb.WriteString("@edgeCollection" + strconv.Itoa(i) + strconv.Itoa(j))
	}

	query := `
FOR path
IN 1..@maxLength ANY K_PATHS
@startVertex TO @targetVertex `
	sb.WriteString(query)
	if len(usingOnly) == 0 {
		values["graph"] = arangoGraph
		sb.WriteString("\nGRAPH @graph")
	} else {
		for i, edge := range usingOnly {
			if i == len(usingOnly)-1 {
				if foundEdgeCollection, ok := mapEdgeToArangoEdgeCollection[edge]; ok {
					for j, edgeCollection := range foundEdgeCollection {
						if j == len(foundEdgeCollection)-1 {
							edgeCollectionWriter(&sb, i, j, edgeCollection)
						} else {
							edgeCollectionWriter(&sb, i, j, edgeCollection)
							sb.WriteString(", ")
						}
					}
				}
			} else {
				if foundEdgeCollection, ok := mapEdgeToArangoEdgeCollection[edge]; ok {
					for j, edgeCollection := range foundEdgeCollection {
						edgeCollectionWriter(&sb, i, j, edgeCollection)
						sb.WriteString(", ")
					}
				}
			}

		}
	}
	sb.WriteString("\nRETURN { nodes: path.vertices[*]._id }")

	cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), values, "Path")
	if err != nil {
		return nil, fmt.Errorf("failed to query path for startNodeID: %s and targetNodeID: %s with error: %w", startNodeID, targetNodeID, err)
	}
	defer cursor.Close()

	type Nodes struct {
		IDs []string `json:"nodes"`
	}

	var pathNodes []Nodes
	for {
		var doc Nodes
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to nodes from cursor: %w", err)
			}
		} else {
			pathNodes = append(pathNodes, doc)
		}
	}

	var foundNodes []model.Node
	for _, nodes := range pathNodes {
		for _, id := range nodes.IDs {
			node, err := c.Node(ctx, id)
			if err != nil {
				return nil, fmt.Errorf("failed to get node for nodeID: %s with error: %w", id, err)
			}
			foundNodes = append(foundNodes, node)
		}
	}
	return foundNodes, nil
}

// TODO (pxp928): investigate if the individual neighbor queries (within nouns and verbs) can be done co-currently
func (c *arangoClient) Neighbors(ctx context.Context, nodeID string, usingOnly []model.Edge) ([]model.Node, error) {
	var neighborsID []string
	var err error

	idSplit := strings.Split(nodeID, "/")
	if len(idSplit) != 2 {
		return nil, fmt.Errorf("invalid ID: %s", nodeID)
	}
	switch idSplit[0] {
	case pkgVersionsStr:
		neighborsID, err = c.packageVersionNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get neighbors for node with id: %s with error: %w", nodeID, err)
		}
	case pkgNamesStr:
		neighborsID, err = c.packageNameNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get neighbors for node with id: %s with error: %w", nodeID, err)
		}
	case pkgNamespacesStr:
		neighborsID, err = c.packageNamespaceNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get neighbors for node with id: %s with error: %w", nodeID, err)
		}
	case pkgTypesStr:
		neighborsID, err = c.packageTypeNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get neighbors for node with id: %s with error: %w", nodeID, err)
		}
	case srcNamesStr:
		neighborsID, err = c.srcNameNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get neighbors for node with id: %s with error: %w", nodeID, err)
		}
	case srcNamespacesStr:
		neighborsID, err = c.srcNamespaceNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get neighbors for node with id: %s with error: %w", nodeID, err)
		}
	case srcTypesStr:
		neighborsID, err = c.srcTypeNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get neighbors for node with id: %s with error: %w", nodeID, err)
		}
	case vulnerabilitiesStr:
		neighborsID, err = c.vulnIdNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get neighbors for node with id: %s with error: %w", nodeID, err)
		}
	case vulnTypesStr:
		neighborsID, err = c.vulnTypeNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get neighbors for node with id: %s with error: %w", nodeID, err)
		}
	case buildersStr:
		neighborsID, err = c.builderNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get neighbors for node with id: %s with error: %w", nodeID, err)
		}
	case artifactsStr:
		neighborsID, err = c.artifactNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get neighbors for node with id: %s with error: %w", nodeID, err)
		}
	case licensesStr:
		neighborsID, err = c.licenseNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get neighbors for node with id: %s with error: %w", nodeID, err)
		}
	case certifyBadsStr:
		neighborsID, err = c.certifyBadNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get neighbors for node with id: %s with error: %w", nodeID, err)
		}
	case certifyGoodsStr:
		return []model.Node{}, nil
	case certifyLegalsStr:
		return []model.Node{}, nil
	case scorecardStr:
		return []model.Node{}, nil
	case certifyVEXsStr:
		return []model.Node{}, nil
	case certifyVulnsStr:
		return []model.Node{}, nil
	case hashEqualsStr:
		return []model.Node{}, nil
	case hasMetadataStr:
		return []model.Node{}, nil
	case hasSBOMsStr:
		return []model.Node{}, nil
	case hasSLSAsStr:
		return []model.Node{}, nil
	case hasSourceAtsStr:
		return []model.Node{}, nil
	case isDependenciesStr:
		return []model.Node{}, nil
	case isOccurrencesStr:
		return []model.Node{}, nil
	case pkgEqualsStr:
		return []model.Node{}, nil
	case pointOfContactStr:
		return []model.Node{}, nil
	case vulnEqualsStr:
		return []model.Node{}, nil
	case vulnMetadataStr:
		return []model.Node{}, nil
	default:
		return nil, fmt.Errorf("unknown ID for node query: %s", nodeID)
	}
	return c.Nodes(ctx, neighborsID)
}

func (c *arangoClient) Node(ctx context.Context, nodeID string) (model.Node, error) {
	idSplit := strings.Split(nodeID, "/")
	if len(idSplit) != 2 {
		return nil, fmt.Errorf("invalid ID: %s", nodeID)
	}
	switch idSplit[0] {
	case pkgVersionsStr, pkgNamesStr, pkgNamespacesStr, pkgTypesStr:
		return c.buildPackageResponseFromID(ctx, nodeID, nil)
	case srcNamesStr, srcNamespacesStr, srcTypesStr:
		return c.buildSourceResponseFromID(ctx, nodeID, nil)
	case vulnerabilitiesStr, vulnTypesStr:
		return c.buildVulnResponseByID(ctx, nodeID, nil)
	case buildersStr:
		return c.buildBuilderResponseByID(ctx, nodeID, nil)
	case artifactsStr:
		return c.buildArtifactResponseByID(ctx, nodeID, nil)
	case licensesStr:
		return c.getLicenseByID(ctx, nodeID)
	case certifyBadsStr:
		return c.buildCertifyBadByID(ctx, nodeID, nil)
	case certifyGoodsStr:
		return c.buildCertifyGoodByID(ctx, nodeID, nil)
	case certifyLegalsStr:
		return c.buildCertifyLegalByID(ctx, nodeID, nil)
	case scorecardStr:
		return c.buildCertifyScorecardByID(ctx, nodeID, nil)
	case certifyVEXsStr:
		return c.buildCertifyVexByID(ctx, nodeID, nil)
	case certifyVulnsStr:
		return c.buildCertifyVulnByID(ctx, nodeID, nil)
	case hashEqualsStr:
		return c.buildHashEqualByID(ctx, nodeID, nil)
	case hasMetadataStr:
		return c.buildHasMetadataByID(ctx, nodeID, nil)
	case hasSBOMsStr:
		return c.buildHasSbomByID(ctx, nodeID, nil)
	case hasSLSAsStr:
		return c.buildHasSlsaByID(ctx, nodeID, nil)
	case hasSourceAtsStr:
		return c.buildHasSourceAtByID(ctx, nodeID, nil)
	case isDependenciesStr:
		return c.buildIsDependencyByID(ctx, nodeID, nil)
	case isOccurrencesStr:
		return c.buildIsOccurrenceByID(ctx, nodeID, nil)
	case pkgEqualsStr:
		return c.buildPkgEqualByID(ctx, nodeID, nil)
	case pointOfContactStr:
		return c.buildPointOfContactByID(ctx, nodeID, nil)
	case vulnEqualsStr:
		return c.buildVulnEqualByID(ctx, nodeID, nil)
	case vulnMetadataStr:
		return c.buildVulnerabilityMetadataByID(ctx, nodeID, nil)
	default:
		return nil, fmt.Errorf("unknown ID for node query: %s", nodeID)
	}
}

func (c *arangoClient) Nodes(ctx context.Context, nodeIDs []string) ([]model.Node, error) {
	rv := make([]model.Node, 0, len(nodeIDs))
	for _, id := range nodeIDs {
		n, err := c.Node(ctx, id)
		if err != nil {
			return nil, err
		}
		rv = append(rv, n)
	}
	return rv, nil
}
