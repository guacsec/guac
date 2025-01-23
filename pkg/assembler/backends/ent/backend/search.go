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
	"sort"
	"time"

	"entgo.io/contrib/entgql"
	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifylegal"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifyvuln"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/dependency"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/hasmetadata"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcename"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

const (
	guacType string = "guac"
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

func notGUACTypePackagePredicates() predicate.PackageVersion {
	return packageversion.And(
		packageversion.HasNameWith(
			optionalPredicate(ptrfrom.String(guacType), packagename.TypeNEQ),
		),
	)
}

func (b *EntBackend) FindPackagesThatNeedScanning(ctx context.Context, queryType model.QueryType, lastScan *int) ([]string, error) {
	var pkgLatestScan []struct {
		ID             uuid.UUID `json:"id"`
		LastScanTimeDB time.Time `json:"max"`
	}

	if queryType == model.QueryTypeVulnerability {
		err := b.client.PackageVersion.Query().
			Where(notGUACTypePackagePredicates()).
			WithName(func(q *ent.PackageNameQuery) {}).
			GroupBy(packageversion.FieldID). // Group by Package ID
			Aggregate(func(s *sql.Selector) string {
				t := sql.Table(certifyvuln.Table)
				s.LeftJoin(t).On(s.C(packageversion.FieldID), t.C(certifyvuln.PackageColumn))
				return sql.As(sql.Max(t.C(certifyvuln.FieldTimeScanned)), "max")
			}).
			Scan(ctx, &pkgLatestScan)

		if err != nil {
			return nil, fmt.Errorf("failed aggregate packages based on certifyVuln with error: %w", err)
		}
	} else if queryType == model.QueryTypeLicense {
		err := b.client.PackageVersion.Query().
			Where(notGUACTypePackagePredicates()).
			WithName(func(q *ent.PackageNameQuery) {}).
			GroupBy(packageversion.FieldID). // Group by Package ID
			Aggregate(func(s *sql.Selector) string {
				t := sql.Table(certifylegal.Table)
				s.LeftJoin(t).On(s.C(packageversion.FieldID), t.C(certifylegal.PackageColumn))
				return sql.As(sql.Max(t.C(certifylegal.FieldTimeScanned)), "max")
			}).
			Scan(ctx, &pkgLatestScan)

		if err != nil {
			return nil, fmt.Errorf("failed aggregate packages based on certifyLegal with error: %w", err)
		}
	} else { // queryType == model.QueryTypeEol via hasMetadata
		err := b.client.PackageVersion.Query().
			Where(notGUACTypePackagePredicates()).
			WithName(func(q *ent.PackageNameQuery) {}).
			GroupBy(packageversion.FieldID). // Group by Package ID
			Aggregate(func(s *sql.Selector) string {
				t := sql.Table(hasmetadata.Table)
				s.LeftJoin(t).On(s.C(packageversion.FieldID), t.C(hasmetadata.FieldPackageVersionID))
				s.Where(sql.And(
					sql.NotNull(t.C(hasmetadata.FieldTimestamp)),
					sql.EQ(t.C(hasmetadata.FieldKey), "endoflife"),
				))
				return sql.As(sql.Max(t.C(hasmetadata.FieldTimestamp)), "max")
			}).
			Scan(ctx, &pkgLatestScan)

		if err != nil {
			return nil, fmt.Errorf("failed aggregate packages based on hasMetadata with error: %w", err)
		}
	}

	var packagesThatNeedScanning []string
	if lastScan == nil {
		for _, record := range pkgLatestScan {
			packagesThatNeedScanning = append(packagesThatNeedScanning, record.ID.String()) // Add the package ID
		}
	} else {
		lastScanTime := time.Now().Add(time.Duration(-*lastScan) * time.Hour).UTC()
		for _, record := range pkgLatestScan {
			if record.LastScanTimeDB.Before(lastScanTime) {
				packagesThatNeedScanning = append(packagesThatNeedScanning, record.ID.String()) // Add the package ID
			}
		}
	}
	return packagesThatNeedScanning, nil
}

func (b *EntBackend) QueryPackagesListForScan(ctx context.Context, pkgIDs []string, after *string, first *int) (*model.PackageConnection, error) {
	var afterCursor *entgql.Cursor[uuid.UUID]

	// if empty pkgIDs slice is passed in return nothing
	if len(pkgIDs) == 0 {
		return nil, nil
	}

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
	if first == nil {
		first = ptrfrom.Int(60000)
	}

	// Sort the UUID slice
	sort.Strings(pkgIDs)

	startIndex := 0
	if after != nil {
		filterGlobalID := fromGlobalID(*after)
		// Find the index of the specified UUID
		startIndex = findTargetIndex(pkgIDs, filterGlobalID.id)
		if startIndex == -1 {
			return nil, nil
		}
	}

	startAfterPackageIDList := pkgIDs[startIndex:]

	var shortenedQueryList []uuid.UUID
	// Loop through the sorted list starting from the specified UUID
	for i, id := range startAfterPackageIDList {
		if i < *first {
			convertedID, err := uuid.Parse(id)
			if err != nil {
				return nil, fmt.Errorf("failed to parse ID to UUID with error: %w", err)
			}
			shortenedQueryList = append(shortenedQueryList, convertedID)
		}
	}

	if len(shortenedQueryList) > 0 {
		var queryErr error
		pkgConn, queryErr = b.client.PackageVersion.Query().
			Where(packageversion.IDIn(shortenedQueryList...)).
			WithName(func(q *ent.PackageNameQuery) {}).
			Paginate(ctx, afterCursor, first, nil, nil)

		if queryErr != nil {
			return nil, fmt.Errorf("failed package query based on package IDs that need scanning with error: %w", queryErr)
		}
	}

	// if not found return nil
	if pkgConn == nil {
		return nil, nil
	}

	hasNextPage := true
	if (startIndex + *first) > len(pkgIDs) {
		hasNextPage = false
	}

	return constructPkgConn(pkgConn, len(pkgIDs), hasNextPage), nil
}

func constructPkgConn(pkgConn *ent.PackageVersionConnection, totalCount int, hasNextPage bool) *model.PackageConnection {

	var edges []*model.PackageEdge
	for _, edge := range pkgConn.Edges {
		edges = append(edges, &model.PackageEdge{
			Cursor: pkgVersionGlobalID(edge.Cursor.ID.String()),
			Node:   toModelPackage(backReferencePackageVersion(edge.Node)),
		})
	}

	if pkgConn.PageInfo.StartCursor != nil {
		return &model.PackageConnection{
			TotalCount: totalCount,
			PageInfo: &model.PageInfo{
				HasNextPage: hasNextPage,
				StartCursor: ptrfrom.String(pkgVersionGlobalID(pkgConn.PageInfo.StartCursor.ID.String())),
				EndCursor:   ptrfrom.String(pkgVersionGlobalID(pkgConn.PageInfo.EndCursor.ID.String())),
			},
			Edges: edges,
		}
	} else {
		// if not found return nil
		return nil
	}
}

func (b *EntBackend) BatchQueryPkgIDCertifyVuln(ctx context.Context, pkgIDs []string) ([]*model.CertifyVuln, error) {

	// if empty pkgIDs slice is passed in return nothing
	if len(pkgIDs) == 0 {
		return nil, nil
	}

	var queryList []uuid.UUID

	for _, id := range pkgIDs {
		globalID := fromGlobalID(id)
		convertedID, err := uuid.Parse(globalID.id)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ID to UUID with error: %w", err)
		}
		queryList = append(queryList, convertedID)
	}

	var aggPredicates []predicate.CertifyVuln
	aggPredicates = append(aggPredicates, certifyvuln.PackageIDIn(queryList...))

	var collectedCertVuln []*model.CertifyVuln
	certVulnConn, err := b.client.CertifyVuln.Query().
		Where(certifyvuln.And(aggPredicates...)).
		WithVulnerability(func(query *ent.VulnerabilityIDQuery) {}).
		WithPackage(func(q *ent.PackageVersionQuery) {
			q.WithName(func(q *ent.PackageNameQuery) {})
		}).All(ctx)

	if err != nil {
		return nil, fmt.Errorf("failed certifyVuln query based on package IDs with error: %w", err)
	}
	for _, entCertVuln := range certVulnConn {
		collectedCertVuln = append(collectedCertVuln, toModelCertifyVulnerability(entCertVuln))
	}
	return collectedCertVuln, nil
}

func (b *EntBackend) BatchQueryPkgIDCertifyLegal(ctx context.Context, pkgIDs []string) ([]*model.CertifyLegal, error) {

	// if empty pkgIDs slice is passed in return nothing
	if len(pkgIDs) == 0 {
		return nil, nil
	}

	var queryList []uuid.UUID

	for _, id := range pkgIDs {
		globalID := fromGlobalID(id)
		convertedID, err := uuid.Parse(globalID.id)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ID to UUID with error: %w", err)
		}
		queryList = append(queryList, convertedID)
	}

	var aggPredicates []predicate.CertifyLegal
	// aggregate to find the latest timescanned for certifyLegals for list of packages
	aggPredicates = append(aggPredicates, certifylegal.PackageIDIn(queryList...), certifylegal.SourceIDIsNil())

	var collectedCertLegal []*model.CertifyLegal

	certLegalConn, err := b.client.CertifyLegal.Query().
		Where(certifylegal.And(aggPredicates...)).
		WithPackage(func(q *ent.PackageVersionQuery) {
			q.WithName(func(q *ent.PackageNameQuery) {})
		}).
		WithDeclaredLicenses().
		WithDiscoveredLicenses().All(ctx)

	if err != nil {
		return nil, fmt.Errorf("failed certifyLegal query based on package IDs with error: %w", err)
	}

	for _, entCertLegal := range certLegalConn {
		collectedCertLegal = append(collectedCertLegal, toModelCertifyLegal(entCertLegal))
	}

	return collectedCertLegal, nil
}

func (b *EntBackend) BatchQuerySubjectPkgDependency(ctx context.Context, pkgIDs []string) ([]*model.IsDependency, error) {

	// if empty pkgIDs slice is passed in return nothing
	if len(pkgIDs) == 0 {
		return nil, nil
	}

	var queryList []uuid.UUID

	for _, id := range pkgIDs {
		globalID := fromGlobalID(id)
		convertedID, err := uuid.Parse(globalID.id)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ID to UUID with error: %w", err)
		}
		queryList = append(queryList, convertedID)
	}

	idDepConn, err := b.client.Dependency.Query().
		Where(dependency.PackageIDIn(queryList...)).
		WithPackage(withPackageVersionTree()).
		WithDependentPackageVersion(withPackageVersionTree()).All(ctx)

	if err != nil {
		return nil, fmt.Errorf("failed isDependency subject query based on package IDs with error: %w", err)
	}

	var collectedIsDependency []*model.IsDependency
	for _, entIsDep := range idDepConn {
		collectedIsDependency = append(collectedIsDependency, toModelIsDependencyWithBackrefs(entIsDep))
	}
	return collectedIsDependency, nil
}

func (b *EntBackend) BatchQueryDepPkgDependency(ctx context.Context, pkgIDs []string) ([]*model.IsDependency, error) {

	// if empty pkgIDs slice is passed in return nothing
	if len(pkgIDs) == 0 {
		return nil, nil
	}

	var queryList []uuid.UUID

	for _, id := range pkgIDs {
		globalID := fromGlobalID(id)
		convertedID, err := uuid.Parse(globalID.id)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ID to UUID with error: %w", err)
		}
		queryList = append(queryList, convertedID)
	}

	idDepConn, err := b.client.Dependency.Query().
		Where(dependency.DependentPackageVersionIDIn(queryList...)).
		WithPackage(withPackageVersionTree()).
		WithDependentPackageVersion(withPackageVersionTree()).All(ctx)

	if err != nil {
		return nil, fmt.Errorf("failed isDependency subject query based on package IDs with error: %w", err)
	}

	var collectedIsDependency []*model.IsDependency
	for _, entIsDep := range idDepConn {
		collectedIsDependency = append(collectedIsDependency, toModelIsDependencyWithBackrefs(entIsDep))
	}
	return collectedIsDependency, nil
}
