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
	"strings"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (c *arangoClient) Path(ctx context.Context, startNodeID string, targetNodeID string, maxPathLength int, usingOnly []model.Edge) ([]model.Node, error) {
	panic(fmt.Errorf("not implemented: Path"))
}

func (c *arangoClient) Neighbors(ctx context.Context, nodeID string, usingOnly []model.Edge) ([]model.Node, error) {
	panic(fmt.Errorf("not implemented: Neighbors"))
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
