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
	"time"

	"entgo.io/contrib/entgql"
	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifylegal"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifyvuln"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcename"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// FindSoftware takes in a searchText string and looks for software
// that may be relevant for the input text. This can be seen as fuzzy search
// function for Packages, Sources and Artifacts. findSoftware returns a list
// of Packages, Sources and Artifacts that it determines to be relevant to
// the input searchText.

// Due to the nature of full text search being implemented differently on
// different db platforms, the behavior of findSoftware is not guaranteed
// to be the same. In addition, their statistical nature may result in
// results being different per call and not reproducible.

// All that is asked in the implementation of this API is that it follows
// the spirit of helping to retrieve the right nodes with best effort.

// Warning: This is an EXPERIMENTAL feature. This is subject to change.
// Warning: This is an OPTIONAL feature. Backends are not required to
// implement this API.
func (b *EntBackend) FindSoftware(ctx context.Context, searchText string) ([]model.PackageSourceOrArtifact, error) {
	// Arbitrarily only search if the search text is longer than 2 characters
	// Search Artifacts
	results := make([]model.PackageSourceOrArtifact, 0)
	if len(searchText) <= 2 {
		return results, nil
	}

	// Search by Package Name
	packages, err := b.client.PackageVersion.Query().Where(
		packageversion.HasNameWith(
			packagename.NameContainsFold(searchText),
		),
	).WithName(func(q *ent.PackageNameQuery) {}).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed package version query with err: %w", err)
	}

	results = append(results, collect(packages, func(v *ent.PackageVersion) model.PackageSourceOrArtifact {
		return toModelPackage(backReferencePackageVersion(v))
	})...)

	// Search Sources
	sources, err := b.client.SourceName.Query().Where(
		sourcename.Or(
			sourcename.NameContainsFold(searchText),
			sourcename.NamespaceContainsFold(searchText),
		),
	).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed source name query with err: %w", err)
	}
	results = append(results, collect(sources, func(v *ent.SourceName) model.PackageSourceOrArtifact {
		return toModelSource(v)
	})...)

	artifacts, err := b.client.Artifact.Query().Where(
		artifact.DigestContains(searchText),
	).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed artifact query with err: %w", err)
	}

	results = append(results, collect(artifacts, func(v *ent.Artifact) model.PackageSourceOrArtifact {
		return toModelArtifact(v)
	})...)

	return results, nil
}

func (b *EntBackend) FindSoftwareList(ctx context.Context, searchText string, after *string, first *int) (*model.FindSoftwareConnection, error) {
	return nil, fmt.Errorf("not implemented: FindSoftwareList")
}

func (b *EntBackend) QueryPackagesListForScan(ctx context.Context, pkgSpec model.PkgSpec, queryType model.QueryType, lastScan *int, after *string, first *int) (*model.PackageConnection, error) {
	var afterCursor *entgql.Cursor[uuid.UUID]

	if after != nil {
		globalID := fromGlobalID(*after)
		if globalID.nodeType != packageversion.Table {
			return nil, fmt.Errorf("after cursor is not type packageversion but type: %s", globalID.nodeType)
		}
		afterUUID, err := uuid.Parse(globalID.id)
		if err != nil {
			return nil, fmt.Errorf("failed to parse global ID with error: %w", err)
		}
		afterCursor = &ent.Cursor{ID: afterUUID}
	} else {
		afterCursor = nil
	}

	var pkgConn *ent.PackageVersionConnection
	if lastScan == nil {
		var err error
		pkgQuery := b.client.PackageVersion.Query().
			Where(packageQueryPredicates(&pkgSpec))

		pkgConn, err = pkgQuery.
			WithName(func(q *ent.PackageNameQuery) {}).
			Paginate(ctx, afterCursor, first, nil, nil)

		if err != nil {
			return nil, fmt.Errorf("failed package query with error: %w", err)
		}
	} else {
		var pkgLatestScan []struct {
			ID             uuid.UUID `json:"id"`
			LastScanTimeDB time.Time `json:"max"`
		}

		if queryType == model.QueryTypeVulnerability {
			err := b.client.PackageVersion.Query().
				Where(packageQueryPredicates(&pkgSpec)).
				GroupBy(packageversion.FieldID). // Group by Package ID
				Aggregate(func(s *sql.Selector) string {
					t := sql.Table(certifyvuln.Table)
					s.LeftJoin(t).On(s.C(packageversion.FieldID), t.C(certifyvuln.PackageColumn))
					return sql.As(sql.Max(t.C(certifyvuln.FieldTimeScanned)), "max")
				}).
				Scan(ctx, &pkgLatestScan)

			if err != nil {
				return nil, fmt.Errorf("failed package query with error: %w", err)
			}
		} else {
			err := b.client.PackageVersion.Query().
				Where(packageQueryPredicates(&pkgSpec)).
				GroupBy(packageversion.FieldID). // Group by Package ID
				Aggregate(func(s *sql.Selector) string {
					t := sql.Table(certifylegal.Table)
					s.LeftJoin(t).On(s.C(packageversion.FieldID), t.C(certifylegal.PackageColumn))
					return sql.As(sql.Max(t.C(certifylegal.FieldTimeScanned)), "max")
				}).
				Scan(ctx, &pkgLatestScan)

			if err != nil {
				return nil, fmt.Errorf("failed package query with error: %w", err)
			}
		}

		lastScanTime := time.Now().Add(time.Duration(-*lastScan) * time.Hour).UTC()
		var packagesThatNeedScanning []uuid.UUID
		for _, record := range pkgLatestScan {
			if record.LastScanTimeDB.Before(lastScanTime) {
				packagesThatNeedScanning = append(packagesThatNeedScanning, record.ID) // Add the package ID
			}
		}

		if len(packagesThatNeedScanning) > 0 {
			var queryErr error
			pkgConn, queryErr = b.client.PackageVersion.Query().
				Where(packageversion.IDIn(packagesThatNeedScanning...)).
				WithName(func(q *ent.PackageNameQuery) {}).
				Paginate(ctx, afterCursor, first, nil, nil)

			if queryErr != nil {
				return nil, fmt.Errorf("failed package query with error: %w", queryErr)
			}
		}
	}

	// if not found return nil
	if pkgConn == nil {
		return nil, nil
	}

	var edges []*model.PackageEdge
	for _, edge := range pkgConn.Edges {
		edges = append(edges, &model.PackageEdge{
			Cursor: pkgVersionGlobalID(edge.Cursor.ID.String()),
			Node:   toModelPackage(backReferencePackageVersion(edge.Node)),
		})
	}

	if pkgConn.PageInfo.StartCursor != nil {
		return &model.PackageConnection{
			TotalCount: pkgConn.TotalCount,
			PageInfo: &model.PageInfo{
				HasNextPage: pkgConn.PageInfo.HasNextPage,
				StartCursor: ptrfrom.String(pkgVersionGlobalID(pkgConn.PageInfo.StartCursor.ID.String())),
				EndCursor:   ptrfrom.String(pkgVersionGlobalID(pkgConn.PageInfo.EndCursor.ID.String())),
			},
			Edges: edges,
		}, nil
	} else {
		// if not found return nil
		return nil, nil
	}
}
