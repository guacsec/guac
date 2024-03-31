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
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certification"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"

	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (b *EntBackend) Path(ctx context.Context, subject string, target string, maxPathLength int, usingOnly []model.Edge) ([]model.Node, error) {
	return nil, fmt.Errorf("not implemented: Path")
}

func (b *EntBackend) Neighbors(ctx context.Context, node string, usingOnly []model.Edge) ([]model.Node, error) {
	return nil, nil
}

func (b *EntBackend) Node(ctx context.Context, node string) (model.Node, error) {
	// return uuid if valid, else error
	nodeID, err := uuid.Parse(node)
	if err != nil {
		return nil, fmt.Errorf("uuid conversion from string failed with error: %w", err)
	}

	nodeTypeFromGlobalID := func(ctx context.Context, gID uuid.UUID) (string, error) {
		return nodeTypeFromGlobalID(ctx, gID.String())
	}

	record, err := b.client.Noder(ctx, nodeID, ent.WithNodeType(nodeTypeFromGlobalID))
	if err != nil {
		return nil, err
	}

	switch v := record.(type) {
	case *ent.Artifact:
		return toModelArtifact(v), nil
	case *ent.PackageVersion:
		pv, err := b.client.PackageVersion.Query().
			Where(packageversion.ID(v.ID)).
			WithName(func(q *ent.PackageNameQuery) {}).
			Only(ctx)
		if err != nil {
			return nil, err
		}
		return toModelPackage(backReferencePackageVersion(pv)), nil
	case *ent.PackageName:
		pn, err := b.client.PackageName.Query().
			Where(packagename.ID(v.ID)).
			WithVersions().
			Only(ctx)
		if err != nil {
			return nil, err
		}
		return toModelPackage(backReferencePackageName(pn)), nil
	case *ent.SourceName:
		return toModelSourceName(v), nil
	case *ent.Builder:
		return toModelBuilder(v), nil
	case *ent.License:
		return toModelLicense(v), nil
	case *ent.VulnerabilityID:
		return toModelVulnerabilityFromVulnerabilityID(v), nil
	case *ent.Certification:
		cert, err := b.client.Certification.Query().
			Where(certification.ID(v.ID)).
			Limit(MaxPageSize).
			WithSource(withSourceNameTreeQuery()).
			WithArtifact().
			WithPackageVersion(withPackageVersionTree()).
			WithAllVersions(withPackageNameTree()).
			Only(ctx)
		if err != nil {
			return nil, err
		}
		if cert.Type == certification.TypeBAD {
			return toModelCertifyBad(cert), nil
		} else {
			return toModelCertifyGood(cert), nil
		}
	case *ent.CertifyLegal:
		legals, err := b.CertifyLegal(ctx, &model.CertifyLegalSpec{ID: ptrfrom.String(v.ID.String())})
		if err != nil {
			return nil, fmt.Errorf("failed to query for CertifyLegal via ID: %s, with error: %w", v.ID.String(), err)
		}
		if len(legals) == 1 {
			return nil, fmt.Errorf("ID returned multiple CertifyLegal nodes %s", v.ID.String())
		}
		return legals[0], nil
	case *ent.CertifyScorecard:
		scores, err := b.Scorecards(ctx, &model.CertifyScorecardSpec{ID: ptrfrom.String(v.ID.String())})
		if err != nil {
			return nil, fmt.Errorf("failed to query for scorecard via ID: %s, with error: %w", v.ID.String(), err)
		}
		if len(scores) == 1 {
			return nil, fmt.Errorf("ID returned multiple scorecard nodes %s", v.ID.String())
		}
		return scores[0], nil
	case *ent.CertifyVex:
		vexs, err := b.CertifyVEXStatement(ctx, &model.CertifyVEXStatementSpec{ID: ptrfrom.String(v.ID.String())})
		if err != nil {
			return nil, fmt.Errorf("failed to query for CertifyVEXStatement via ID: %s, with error: %w", v.ID.String(), err)
		}
		if len(vexs) == 1 {
			return nil, fmt.Errorf("ID returned multiple CertifyVEXStatement nodes %s", v.ID.String())
		}
		return vexs[0], nil
	case *ent.CertifyVuln:
		vulns, err := b.CertifyVuln(ctx, &model.CertifyVulnSpec{ID: ptrfrom.String(v.ID.String())})
		if err != nil {
			return nil, fmt.Errorf("failed to query for CertifyVuln via ID: %s, with error: %w", v.ID.String(), err)
		}
		if len(vulns) == 1 {
			return nil, fmt.Errorf("ID returned multiple CertifyVuln nodes %s", v.ID.String())
		}
		return vulns[0], nil
	case *ent.HashEqual:
		hes, err := b.HashEqual(ctx, &model.HashEqualSpec{ID: ptrfrom.String(v.ID.String())})
		if err != nil {
			return nil, fmt.Errorf("failed to query for HashEqual via ID: %s, with error: %w", v.ID.String(), err)
		}
		if len(hes) == 1 {
			return nil, fmt.Errorf("ID returned multiple HashEqual nodes %s", v.ID.String())
		}
		return hes[0], nil
	case *ent.HasMetadata:
		hms, err := b.HasMetadata(ctx, &model.HasMetadataSpec{ID: ptrfrom.String(v.ID.String())})
		if err != nil {
			return nil, fmt.Errorf("failed to query for HasMetadata via ID: %s, with error: %w", v.ID.String(), err)
		}
		if len(hms) == 1 {
			return nil, fmt.Errorf("ID returned multiple HasMetadata nodes %s", v.ID.String())
		}
		return hms[0], nil
	case *ent.BillOfMaterials:
		hbs, err := b.HasSBOM(ctx, &model.HasSBOMSpec{ID: ptrfrom.String(v.ID.String())})
		if err != nil {
			return nil, fmt.Errorf("failed to query for HasSBOM via ID: %s, with error: %w", v.ID.String(), err)
		}
		if len(hbs) == 1 {
			return nil, fmt.Errorf("ID returned multiple HasSBOM nodes %s", v.ID.String())
		}
		return hbs[0], nil
	case *ent.SLSAAttestation:
		slsas, err := b.HasSlsa(ctx, &model.HasSLSASpec{ID: ptrfrom.String(v.ID.String())})
		if err != nil {
			return nil, fmt.Errorf("failed to query for HasSlsa via ID: %s, with error: %w", v.ID.String(), err)
		}
		if len(slsas) == 1 {
			return nil, fmt.Errorf("ID returned multiple HasSlsa nodes %s", v.ID.String())
		}
		return slsas[0], nil
	case *ent.HasSourceAt:
		hsas, err := b.HasSourceAt(ctx, &model.HasSourceAtSpec{ID: ptrfrom.String(v.ID.String())})
		if err != nil {
			return nil, fmt.Errorf("failed to query for HasSourceAt via ID: %s, with error: %w", v.ID.String(), err)
		}
		if len(hsas) == 1 {
			return nil, fmt.Errorf("ID returned multiple HasSourceAt nodes %s", v.ID.String())
		}
		return hsas[0], nil
	case *ent.Dependency:
		deps, err := b.IsDependency(ctx, &model.IsDependencySpec{ID: ptrfrom.String(v.ID.String())})
		if err != nil {
			return nil, fmt.Errorf("failed to query for IsDependency via ID: %s, with error: %w", v.ID.String(), err)
		}
		if len(deps) == 1 {
			return nil, fmt.Errorf("ID returned multiple IsDependency nodes %s", v.ID.String())
		}
		return deps[0], nil
	case *ent.Occurrence:
		occurs, err := b.IsOccurrence(ctx, &model.IsOccurrenceSpec{ID: ptrfrom.String(v.ID.String())})
		if err != nil {
			return nil, fmt.Errorf("failed to query for IsOccurrence via ID: %s, with error: %w", v.ID.String(), err)
		}
		if len(occurs) == 1 {
			return nil, fmt.Errorf("ID returned multiple IsOccurrence nodes %s", v.ID.String())
		}
		return occurs[0], nil
	case *ent.PkgEqual:
		pes, err := b.PkgEqual(ctx, &model.PkgEqualSpec{ID: ptrfrom.String(v.ID.String())})
		if err != nil {
			return nil, fmt.Errorf("failed to query for PkgEqual via ID: %s, with error: %w", v.ID.String(), err)
		}
		if len(pes) == 1 {
			return nil, fmt.Errorf("ID returned multiple PkgEqual nodes %s", v.ID.String())
		}
		return pes[0], nil
	case *ent.PointOfContact:
		pocs, err := b.PointOfContact(ctx, &model.PointOfContactSpec{ID: ptrfrom.String(v.ID.String())})
		if err != nil {
			return nil, fmt.Errorf("failed to query for PointOfContact via ID: %s, with error: %w", v.ID.String(), err)
		}
		if len(pocs) == 1 {
			return nil, fmt.Errorf("ID returned multiple PointOfContact nodes %s", v.ID.String())
		}
		return pocs[0], nil
	case *ent.VulnEqual:
		ves, err := b.VulnEqual(ctx, &model.VulnEqualSpec{ID: ptrfrom.String(v.ID.String())})
		if err != nil {
			return nil, fmt.Errorf("failed to query for VulnEqual via ID: %s, with error: %w", v.ID.String(), err)
		}
		if len(ves) == 1 {
			return nil, fmt.Errorf("ID returned multiple VulnEqual nodes %s", v.ID.String())
		}
		return ves[0], nil
	case *ent.VulnerabilityMetadata:
		vms, err := b.VulnerabilityMetadata(ctx, &model.VulnerabilityMetadataSpec{ID: ptrfrom.String(v.ID.String())})
		if err != nil {
			return nil, fmt.Errorf("failed to query for VulnerabilityMetadata via ID: %s, with error: %w", v.ID.String(), err)
		}
		if len(vms) == 1 {
			return nil, fmt.Errorf("ID returned multiple VulnerabilityMetadata nodes %s", v.ID.String())
		}
		return vms[0], nil
	default:
		log.Printf("Unknown node type: %T", v)
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
