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
	"log"
	"strconv"

	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagenamespace"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagetype"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcetype"

	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (b *EntBackend) Neighbors(ctx context.Context, node string, usingOnly []model.Edge) ([]model.Node, error) {
	return nil, nil
}

func (b *EntBackend) Node(ctx context.Context, node string) (model.Node, error) {
	id, err := strconv.Atoi(node)
	if err != nil {
		return nil, err
	}

	record, err := b.client.Noder(ctx, id)
	if err != nil {
		return nil, err
	}

	switch v := record.(type) {
	case *ent.Artifact:
		return toModelArtifact(v), nil
	case *ent.PackageVersion:
		pv, err := b.client.PackageVersion.Query().
			Where(packageversion.ID(v.ID)).
			WithName(func(q *ent.PackageNameQuery) {
				q.WithNamespace(func(q *ent.PackageNamespaceQuery) {
					q.WithPackage()
				})
			}).
			Only(ctx)
		if err != nil {
			return nil, err
		}
		return toModelPackage(backReferencePackageVersion(pv)), nil
	case *ent.PackageName:
		pn, err := b.client.PackageName.Query().
			Where(packagename.ID(v.ID)).
			WithNamespace(func(q *ent.PackageNamespaceQuery) {
				q.WithPackage()
			}).
			WithVersions().
			Only(ctx)
		if err != nil {
			return nil, err
		}
		return toModelPackage(backReferencePackageName(pn)), nil
	case *ent.PackageNamespace:
		pns, err := b.client.PackageNamespace.Query().
			Where(packagenamespace.ID(v.ID)).
			WithPackage().
			WithNames(func(q *ent.PackageNameQuery) {
				q.WithVersions()
			}).
			Only(ctx)
		if err != nil {
			return nil, err
		}
		return toModelPackage(backReferencePackageNamespace(pns)), nil
	case *ent.PackageType:
		pt, err := b.client.PackageType.Query().
			Where(packagetype.ID(v.ID)).
			WithNamespaces().
			Only(ctx)
		if err != nil {
			return nil, err
		}
		return toModelPackage(pt), nil
	case *ent.SourceType:
		s, err := b.client.SourceType.Query().
			Where(sourcetype.ID(v.ID)).
			WithNamespaces().
			Only(ctx)
		if err != nil {
			return nil, err
		}
		return toModelSource(s), nil
	case *ent.SourceName:
		s, err := b.client.SourceName.Query().
			Where(sourcename.IDIn(v.ID)).
			WithNamespace(func(q *ent.SourceNamespaceQuery) {
				q.WithSourceType()
			}).
			Only(ctx)
		if err != nil {
			return nil, err
		}
		return toModelSourceName(s), nil
	case *ent.Builder:
		return toModelBuilder(v), nil
	case *ent.VulnerabilityType:
		return toModelVulnerability(v), nil
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
