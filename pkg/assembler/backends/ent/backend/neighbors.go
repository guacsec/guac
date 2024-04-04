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

package backend

import (
	"context"
	"fmt"
	"log"

	"github.com/google/uuid"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/billofmaterials"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/builder"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifylegal"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifyscorecard"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifyvex"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifyvuln"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/dependency"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/hashequal"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/hasmetadata"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/hassourceat"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/license"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/occurrence"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/pkgequal"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/pointofcontact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/slsaattestation"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnequal"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnerabilityid"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnerabilitymetadata"

	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (b *EntBackend) Path(ctx context.Context, subject string, target string, maxPathLength int, usingOnly []model.Edge) ([]model.Node, error) {
	return nil, fmt.Errorf("not implemented: Path")
}

func (b *EntBackend) Neighbors(ctx context.Context, nodeID string, usingOnly []model.Edge) ([]model.Node, error) {
	var neighbors []model.Node
	var err error

	foundGlobalID := fromGlobalID(nodeID)
	if foundGlobalID.nodeType == "" {
		return nil, fmt.Errorf("failed to parse globalID %s. Missing Node Type", nodeID)
	}
	switch foundGlobalID.nodeType {
	case packageversion.Table:
		neighbors, err = b.packageVersionNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get pkgVersion neighbors with id: %s with error: %w", nodeID, err)
		}
	case packagename.Table:
		neighbors, err = b.packageNameNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get pkgName neighbors with id: %s with error: %w", nodeID, err)
		}
	case pkgNamespaceString:
		neighbors, err = b.packageNamespaceNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get pkgNamespace neighbors with id: %s with error: %w", nodeID, err)
		}
	case pkgTypeString:
		neighbors, err = b.packageTypeNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get pkgType neighbors with id: %s with error: %w", nodeID, err)
		}
	case sourcename.Table:
		neighbors, err = b.srcNameNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get source name neighbors with id: %s with error: %w", nodeID, err)
		}
	case srcNamespaceString:
		neighbors, err = b.srcNamespaceNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get source namespace neighbors with id: %s with error: %w", nodeID, err)
		}
	case srcTypeString:
		neighbors, err = b.srcTypeNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get source type neighbors with id: %s with error: %w", nodeID, err)
		}
	case vulnerabilityid.Table:
		neighbors, err = b.vulnIdNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get vulnID neighbors with id: %s with error: %w", nodeID, err)
		}
	case vulnTypeString:
		neighbors, err = b.vulnTypeNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get vuln type neighbors with id: %s with error: %w", nodeID, err)
		}
	case builder.Table:
		neighbors, err = b.builderNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get builder neighbors with id: %s with error: %w", nodeID, err)
		}
	case artifact.Table:
		neighbors, err = b.artifactNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get artifact neighbors with id: %s with error: %w", nodeID, err)
		}
	case license.Table:
		neighbors, err = b.licenseNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get license neighbors with id: %s with error: %w", nodeID, err)
		}
	case certifyBadString:
		neighbors, err = b.certifyBadNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get certifyBad neighbors with id: %s with error: %w", nodeID, err)
		}
	case certifyGoodString:
		neighbors, err = b.certifyGoodNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get certifyGood neighbors with id: %s with error: %w", nodeID, err)
		}
	case certifylegal.Table:
		neighbors, err = b.certifyLegalNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get certifyLegal neighbors with id: %s with error: %w", nodeID, err)
		}
	case certifyscorecard.Table:
		neighbors, err = b.certifyScorecardNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get neighbors with id: %s with error: %w", nodeID, err)
		}
	case certifyvex.Table:
		neighbors, err = b.certifyVexNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get certifyVex neighbors with id: %s with error: %w", nodeID, err)
		}
	case certifyvuln.Table:
		neighbors, err = b.certifyVulnNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get neighbors with id: %s with error: %w", nodeID, err)
		}
	case hashequal.Table:
		neighbors, err = b.hashEqualNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get neighbors with id: %s with error: %w", nodeID, err)
		}
	case hasmetadata.Table:
		neighbors, err = b.hasMetadataNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get neighbors with id: %s with error: %w", nodeID, err)
		}
	case billofmaterials.Table:
		neighbors, err = b.hasSbomNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get neighbors with id: %s with error: %w", nodeID, err)
		}
	// case hasSLSAsStr:
	// 	neighbors, err = c.hasSlsaNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
	// 	if err != nil {
	// 		return []model.Node{}, fmt.Errorf("failed to get neighbors with id: %s with error: %w", nodeID, err)
	// 	}
	// case hasSourceAtsStr:
	// 	neighbors, err = c.hasSourceAtNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
	// 	if err != nil {
	// 		return []model.Node{}, fmt.Errorf("failed to get neighbors with id: %s with error: %w", nodeID, err)
	// 	}
	case dependency.Table:
		neighbors, err = b.isDependencyNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get neighbors with id: %s with error: %w", nodeID, err)
		}
	case occurrence.Table:
		neighbors, err = b.isOccurrenceNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get neighbors with id: %s with error: %w", nodeID, err)
		}
	case pkgequal.Table:
		neighbors, err = b.pkgEqualNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get neighbors with id: %s with error: %w", nodeID, err)
		}
	case pointofcontact.Table:
		neighbors, err = b.pointOfContactNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get neighbors with id: %s with error: %w", nodeID, err)
		}
	// case vulnEqualsStr:
	// 	neighbors, err = c.vulnEqualNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
	// 	if err != nil {
	// 		return []model.Node{}, fmt.Errorf("failed to get neighbors with id: %s with error: %w", nodeID, err)
	// 	}
	// case vulnMetadataStr:
	// 	neighbors, err = c.vulnMetadataNeighbors(ctx, nodeID, processUsingOnly(usingOnly))
	// 	if err != nil {
	// 		return []model.Node{}, fmt.Errorf("failed to get neighbors with id: %s with error: %w", nodeID, err)
	// 	}
	default:
		return nil, fmt.Errorf("unknown ID for neighbors query: %s", nodeID)
	}
	return neighbors, nil
}

func (b *EntBackend) Node(ctx context.Context, node string) (model.Node, error) {
	foundGlobalID := fromGlobalID(node)
	if foundGlobalID.nodeType == "" {
		return nil, fmt.Errorf("failed to parse globalID %s. Missing Node Type", node)
	}
	// return uuid if valid, else error
	nodeID, err := uuid.Parse(foundGlobalID.id)
	if err != nil {
		return nil, fmt.Errorf("uuid conversion from string failed with error: %w", err)
	}

	switch foundGlobalID.nodeType {
	case artifact.Table:
		record, err := b.client.Noder(ctx, nodeID, ent.WithFixedNodeType(foundGlobalID.nodeType))
		if err != nil {
			return nil, err
		}

		if art, ok := record.(*ent.Artifact); ok {
			return toModelArtifact(art), nil
		} else {
			return nil, fmt.Errorf("failed to assert type of artifact")
		}
	case packageversion.Table:
		pv, err := b.client.PackageVersion.Query().
			Where(packageversion.ID(nodeID)).
			WithName(func(q *ent.PackageNameQuery) {}).
			Only(ctx)
		if err != nil {
			return nil, err
		}
		return toModelPackage(backReferencePackageVersion(pv)), nil
	case packagename.Table:
		pn, err := b.client.PackageName.Query().
			Where(packagename.ID(nodeID)).
			WithVersions().
			Only(ctx)
		if err != nil {
			return nil, err
		}
		return toModelPackage(backReferencePackageName(pn)), nil
	case sourcename.Table:
		record, err := b.client.Noder(ctx, nodeID, ent.WithFixedNodeType(foundGlobalID.nodeType))
		if err != nil {
			return nil, err
		}

		if sn, ok := record.(*ent.SourceName); ok {
			return toModelSourceName(sn), nil
		} else {
			return nil, fmt.Errorf("failed to assert type of SourceName")
		}
	case builder.Table:
		record, err := b.client.Noder(ctx, nodeID, ent.WithFixedNodeType(foundGlobalID.nodeType))
		if err != nil {
			return nil, err
		}

		if b, ok := record.(*ent.Builder); ok {
			return toModelBuilder(b), nil
		} else {
			return nil, fmt.Errorf("failed to assert type of Builder")
		}
	case license.Table:
		record, err := b.client.Noder(ctx, nodeID, ent.WithFixedNodeType(foundGlobalID.nodeType))
		if err != nil {
			return nil, err
		}

		if lic, ok := record.(*ent.License); ok {
			return toModelLicense(lic), nil
		} else {
			return nil, fmt.Errorf("failed to assert type of License")
		}
	case vulnerabilityid.Table:
		record, err := b.client.Noder(ctx, nodeID, ent.WithFixedNodeType(foundGlobalID.nodeType))
		if err != nil {
			return nil, err
		}

		if v, ok := record.(*ent.VulnerabilityID); ok {
			return toModelVulnerabilityFromVulnerabilityID(v), nil
		} else {
			return nil, fmt.Errorf("failed to assert type of VulnerabilityID")
		}
	case certifyBadString:
		certs, err := b.CertifyBad(ctx, &model.CertifyBadSpec{ID: ptrfrom.String(nodeID.String())})
		if err != nil {
			return nil, fmt.Errorf("failed to query for CertifyBad via ID: %s, with error: %w", nodeID.String(), err)
		}
		if len(certs) != 1 {
			return nil, fmt.Errorf("ID returned multiple CertifyBad nodes %s", nodeID.String())
		}
		return certs[0], nil
	case certifyGoodString:
		certs, err := b.CertifyGood(ctx, &model.CertifyGoodSpec{ID: ptrfrom.String(nodeID.String())})
		if err != nil {
			return nil, fmt.Errorf("failed to query for CertifyGood via ID: %s, with error: %w", nodeID.String(), err)
		}
		if len(certs) != 1 {
			return nil, fmt.Errorf("ID returned multiple CertifyGood nodes %s", nodeID.String())
		}
		return certs[0], nil
	case certifylegal.Table:
		legals, err := b.CertifyLegal(ctx, &model.CertifyLegalSpec{ID: ptrfrom.String(nodeID.String())})
		if err != nil {
			return nil, fmt.Errorf("failed to query for CertifyLegal via ID: %s, with error: %w", nodeID.String(), err)
		}
		if len(legals) != 1 {
			return nil, fmt.Errorf("ID returned multiple CertifyLegal nodes %s", nodeID.String())
		}
		return legals[0], nil
	case certifyscorecard.Table:
		scores, err := b.Scorecards(ctx, &model.CertifyScorecardSpec{ID: ptrfrom.String(nodeID.String())})
		if err != nil {
			return nil, fmt.Errorf("failed to query for scorecard via ID: %s, with error: %w", nodeID.String(), err)
		}
		if len(scores) != 1 {
			return nil, fmt.Errorf("ID returned multiple scorecard nodes %s", nodeID.String())
		}
		return scores[0], nil
	case certifyvex.Table:
		vexs, err := b.CertifyVEXStatement(ctx, &model.CertifyVEXStatementSpec{ID: ptrfrom.String(nodeID.String())})
		if err != nil {
			return nil, fmt.Errorf("failed to query for CertifyVEXStatement via ID: %s, with error: %w", nodeID.String(), err)
		}
		if len(vexs) != 1 {
			return nil, fmt.Errorf("ID returned multiple CertifyVEXStatement nodes %s", nodeID.String())
		}
		return vexs[0], nil
	case certifyvuln.Table:
		vulns, err := b.CertifyVuln(ctx, &model.CertifyVulnSpec{ID: ptrfrom.String(nodeID.String())})
		if err != nil {
			return nil, fmt.Errorf("failed to query for CertifyVuln via ID: %s, with error: %w", nodeID.String(), err)
		}
		if len(vulns) != 1 {
			return nil, fmt.Errorf("ID returned multiple CertifyVuln nodes %s", nodeID.String())
		}
		return vulns[0], nil
	case hashequal.Table:
		hes, err := b.HashEqual(ctx, &model.HashEqualSpec{ID: ptrfrom.String(nodeID.String())})
		if err != nil {
			return nil, fmt.Errorf("failed to query for HashEqual via ID: %s, with error: %w", nodeID.String(), err)
		}
		if len(hes) != 1 {
			return nil, fmt.Errorf("ID returned multiple HashEqual nodes %s", nodeID.String())
		}
		return hes[0], nil
	case hasmetadata.Table:
		hms, err := b.HasMetadata(ctx, &model.HasMetadataSpec{ID: ptrfrom.String(nodeID.String())})
		if err != nil {
			return nil, fmt.Errorf("failed to query for HasMetadata via ID: %s, with error: %w", nodeID.String(), err)
		}
		if len(hms) != 1 {
			return nil, fmt.Errorf("ID returned multiple HasMetadata nodes %s", nodeID.String())
		}
		return hms[0], nil
	case billofmaterials.Table:
		hbs, err := b.HasSBOM(ctx, &model.HasSBOMSpec{ID: ptrfrom.String(nodeID.String())})
		if err != nil {
			return nil, fmt.Errorf("failed to query for HasSBOM via ID: %s, with error: %w", nodeID.String(), err)
		}
		if len(hbs) != 1 {
			return nil, fmt.Errorf("ID returned multiple HasSBOM nodes %s", nodeID.String())
		}
		return hbs[0], nil
	case slsaattestation.Table:
		slsas, err := b.HasSlsa(ctx, &model.HasSLSASpec{ID: ptrfrom.String(nodeID.String())})
		if err != nil {
			return nil, fmt.Errorf("failed to query for HasSlsa via ID: %s, with error: %w", nodeID.String(), err)
		}
		if len(slsas) != 1 {
			return nil, fmt.Errorf("ID returned multiple HasSlsa nodes %s", nodeID.String())
		}
		return slsas[0], nil
	case hassourceat.Table:
		hsas, err := b.HasSourceAt(ctx, &model.HasSourceAtSpec{ID: ptrfrom.String(nodeID.String())})
		if err != nil {
			return nil, fmt.Errorf("failed to query for HasSourceAt via ID: %s, with error: %w", nodeID.String(), err)
		}
		if len(hsas) != 1 {
			return nil, fmt.Errorf("ID returned multiple HasSourceAt nodes %s", nodeID.String())
		}
		return hsas[0], nil
	case dependency.Table:
		deps, err := b.IsDependency(ctx, &model.IsDependencySpec{ID: ptrfrom.String(nodeID.String())})
		if err != nil {
			return nil, fmt.Errorf("failed to query for IsDependency via ID: %s, with error: %w", nodeID.String(), err)
		}
		if len(deps) != 1 {
			return nil, fmt.Errorf("ID returned multiple IsDependency nodes %s", nodeID.String())
		}
		return deps[0], nil
	case occurrence.Table:
		occurs, err := b.IsOccurrence(ctx, &model.IsOccurrenceSpec{ID: ptrfrom.String(nodeID.String())})
		if err != nil {
			return nil, fmt.Errorf("failed to query for IsOccurrence via ID: %s, with error: %w", nodeID.String(), err)
		}
		if len(occurs) != 1 {
			return nil, fmt.Errorf("ID returned multiple IsOccurrence nodes %s", nodeID.String())
		}
		return occurs[0], nil
	case pkgequal.Table:
		pes, err := b.PkgEqual(ctx, &model.PkgEqualSpec{ID: ptrfrom.String(nodeID.String())})
		if err != nil {
			return nil, fmt.Errorf("failed to query for PkgEqual via ID: %s, with error: %w", nodeID.String(), err)
		}
		if len(pes) != 1 {
			return nil, fmt.Errorf("ID returned multiple PkgEqual nodes %s", nodeID.String())
		}
		return pes[0], nil
	case pointofcontact.Table:
		pocs, err := b.PointOfContact(ctx, &model.PointOfContactSpec{ID: ptrfrom.String(nodeID.String())})
		if err != nil {
			return nil, fmt.Errorf("failed to query for PointOfContact via ID: %s, with error: %w", nodeID.String(), err)
		}
		if len(pocs) != 1 {
			return nil, fmt.Errorf("ID returned multiple PointOfContact nodes %s", nodeID.String())
		}
		return pocs[0], nil
	case vulnequal.Table:
		ves, err := b.VulnEqual(ctx, &model.VulnEqualSpec{ID: ptrfrom.String(nodeID.String())})
		if err != nil {
			return nil, fmt.Errorf("failed to query for VulnEqual via ID: %s, with error: %w", nodeID.String(), err)
		}
		if len(ves) != 1 {
			return nil, fmt.Errorf("ID returned multiple VulnEqual nodes %s", nodeID.String())
		}
		return ves[0], nil
	case vulnerabilitymetadata.Table:
		vms, err := b.VulnerabilityMetadata(ctx, &model.VulnerabilityMetadataSpec{ID: ptrfrom.String(nodeID.String())})
		if err != nil {
			return nil, fmt.Errorf("failed to query for VulnerabilityMetadata via ID: %s, with error: %w", nodeID.String(), err)
		}
		if len(vms) != 1 {
			return nil, fmt.Errorf("ID returned multiple VulnerabilityMetadata nodes %s", nodeID.String())
		}
		return vms[0], nil
	default:
		log.Printf("Unknown node type: %s", foundGlobalID.nodeType)
	}
	return nil, nil
}

func (b *EntBackend) Nodes(ctx context.Context, nodes []string) ([]model.Node, error) {
	rv := make([]model.Node, 0, len(nodes))
	for _, id := range nodes {
		n, err := b.Node(ctx, id)
		if err != nil {
			return nil, err
		}
		rv = append(rv, n)
	}
	return rv, nil
}

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
