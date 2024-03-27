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
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certification"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"

	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (b *EntBackend) Neighbors(ctx context.Context, node string, usingOnly []model.Edge) ([]model.Node, error) {
	return nil, nil
}

func (b *EntBackend) Node(ctx context.Context, node string) (model.Node, error) {
	nodID, err := uuid.Parse(node)
	if err != nil {
		return nil, fmt.Errorf("uuid conversion from string failed with error: %w", err)
	}

	record, err := b.client.Noder(ctx, nodID)
	if err != nil {
		return nil, err
	}

	// switch idSplit[0] {
	// case certifyLegalsStr:
	// 	return c.buildCertifyLegalByID(ctx, nodeID, nil)
	// case scorecardStr:
	// 	return c.buildCertifyScorecardByID(ctx, nodeID, nil)
	// case certifyVEXsStr:
	// 	return c.buildCertifyVexByID(ctx, nodeID, nil)
	// case certifyVulnsStr:
	// 	return c.buildCertifyVulnByID(ctx, nodeID, nil)
	// case hashEqualsStr:
	// 	return c.buildHashEqualByID(ctx, nodeID, nil)
	// case hasMetadataStr:
	// 	return c.buildHasMetadataByID(ctx, nodeID, nil)
	// case hasSBOMsStr:
	// 	return c.buildHasSbomByID(ctx, nodeID, nil)
	// case hasSLSAsStr:
	// 	return c.buildHasSlsaByID(ctx, nodeID, nil)
	// case hasSourceAtsStr:
	// 	return c.buildHasSourceAtByID(ctx, nodeID, nil)
	// case isDependenciesStr:
	// 	return c.buildIsDependencyByID(ctx, nodeID, nil)
	// case isOccurrencesStr:
	// 	return c.buildIsOccurrenceByID(ctx, nodeID, nil)
	// case pkgEqualsStr:
	// 	return c.buildPkgEqualByID(ctx, nodeID, nil)
	// case pointOfContactStr:
	// 	return c.buildPointOfContactByID(ctx, nodeID, nil)
	// case vulnEqualsStr:
	// 	return c.buildVulnEqualByID(ctx, nodeID, nil)
	// case vulnMetadataStr:
	// 	return c.buildVulnerabilityMetadataByID(ctx, nodeID, nil)
	// default:
	// 	return nil, fmt.Errorf("unknown ID for node query: %s", nodeID)
	// }

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
