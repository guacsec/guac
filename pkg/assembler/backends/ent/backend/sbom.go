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
	stdsql "database/sql"
	"fmt"
	"strings"

	"entgo.io/contrib/entgql"
	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/billofmaterials"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/dependency"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/occurrence"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

const (
	nodeIncludeSoftware     = "edges.node.includedSoftware"
	nodeIncludeDependencies = "edges.node.includedDependencies"
	nodeIncludeOccurrences  = "edges.node.includedOccurrences"
)

func hasSBOMGlobalID(id string) string {
	return toGlobalID(billofmaterials.Table, id)
}

func bulkHasSBOMGlobalID(ids []string) []string {
	return toGlobalIDs(billofmaterials.Table, ids)
}

func (b *EntBackend) HasSBOMList(ctx context.Context, spec model.HasSBOMSpec, after *string, first *int) (*model.HasSBOMConnection, error) {

	var outputIncludeSoftware bool
	var outputIncludeDependencies bool
	var outputIncludedOccurrences bool

	fields := helper.GetPreloads(ctx)

	for _, f := range fields {
		if f == nodeIncludeSoftware {
			outputIncludeSoftware = true
		}
		if f == nodeIncludeDependencies {
			outputIncludeDependencies = true
		}
		if f == nodeIncludeOccurrences {
			outputIncludedOccurrences = true
		}
	}

	if len(fields) == 0 {
		outputIncludeSoftware = true
		outputIncludeDependencies = true
		outputIncludedOccurrences = true
	}

	var afterCursor *entgql.Cursor[uuid.UUID]

	if after != nil {
		globalID := fromGlobalID(*after)
		afterUUID, err := uuid.Parse(globalID.id)
		if err != nil {
			return nil, err
		}
		afterCursor = &ent.Cursor{ID: afterUUID}
	} else {
		afterCursor = nil
	}

	sbomQuery := b.client.BillOfMaterials.Query().
		Where(hasSBOMQuery(spec))

	hasSBOMConnection, err := getSBOMObjectWithOutIncludes(sbomQuery).Paginate(ctx, afterCursor, first, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed hasSBOM query with error: %w", err)
	}

	// if not found return nil
	if hasSBOMConnection == nil {
		return nil, nil
	}

	// Large SBOMs (50MB+) hit the postgres parameter issue (HasSBOM: pq: got 97137 parameters but PostgreSQL only supports 65535 parameters).
	// To overcome this, we can breakout the "included" pieces of the hasSBOM node into individual queries and reconstruct the node at the end.

	reconstructedSBOMs := map[string]*model.HasSbom{}
	includedFirst := 60000

	type depResult struct {
		deps   []*ent.Dependency
		depErr error
	}

	type occurResult struct {
		occurs   []*ent.Occurrence
		occurErr error
	}

	type pkgVersionResult struct {
		pkgVersions []*ent.PackageVersion
		pkgVerErr   error
	}

	type artResult struct {
		arts   []*ent.Artifact
		artErr error
	}

	for _, foundSBOM := range hasSBOMConnection.Edges {

		var includedDeps []*ent.Dependency
		var includedOccurs []*ent.Occurrence
		var includedPackages []*ent.PackageVersion
		var includedArtifacts []*ent.Artifact

		var depsChan chan depResult
		var occursChan chan occurResult
		var pkgVerChan chan pkgVersionResult
		var artChan chan artResult

		sbomID := foundSBOM.Cursor.ID.String()

		// query included packages
		if outputIncludeSoftware {
			pkgVerChan = make(chan pkgVersionResult, 1)
			artChan = make(chan artResult, 1)
			go func(ctx context.Context, b *EntBackend, sbomID string, first int, pkgChan chan<- pkgVersionResult) {
				var afterCursor *entgql.Cursor[uuid.UUID]
				defer close(pkgChan)
				for {
					pkgConn, err := b.client.PackageVersion.Query().
						Where(packageversion.HasIncludedInSbomsWith([]predicate.BillOfMaterials{
							optionalPredicate(&sbomID, IDEQ)}...)).
						WithName(func(q *ent.PackageNameQuery) {}).Paginate(ctx, afterCursor, &first, nil, nil)
					if err != nil {
						pkgChan <- pkgVersionResult{pkgVersions: nil,
							pkgVerErr: fmt.Errorf("failed included package query for hasSBOM with error: %w", err)}
					}

					// if not found break
					if pkgConn == nil {
						break
					}

					var paginatedPkgs []*ent.PackageVersion
					for _, edge := range pkgConn.Edges {
						paginatedPkgs = append(paginatedPkgs, edge.Node)
					}

					pkgChan <- pkgVersionResult{pkgVersions: paginatedPkgs, pkgVerErr: nil}

					if !pkgConn.PageInfo.HasNextPage {
						break
					}
					afterCursor = pkgConn.PageInfo.EndCursor
				}
			}(ctx, b, sbomID, includedFirst, pkgVerChan)

			// query included artifacts
			go func(ctx context.Context, b *EntBackend, sbomID string, first int, artChan chan<- artResult) {
				var afterCursor *entgql.Cursor[uuid.UUID]
				defer close(artChan)
				for {
					artConn, err := b.client.Artifact.Query().
						Where(artifact.HasIncludedInSbomsWith([]predicate.BillOfMaterials{
							optionalPredicate(&sbomID, IDEQ)}...)).Paginate(ctx, afterCursor, &first, nil, nil)

					if err != nil {
						artChan <- artResult{arts: nil,
							artErr: fmt.Errorf("failed included artifacts query for hasSBOM with error: %w", err)}
					}

					// if not found break
					if artConn == nil {
						break
					}

					var paginatedArts []*ent.Artifact
					for _, edge := range artConn.Edges {
						paginatedArts = append(paginatedArts, edge.Node)
					}

					artChan <- artResult{arts: paginatedArts,
						artErr: nil}

					if !artConn.PageInfo.HasNextPage {
						break
					}
					afterCursor = artConn.PageInfo.EndCursor
				}

			}(ctx, b, sbomID, includedFirst, artChan)
		}

		// query included dependencies
		if outputIncludeDependencies {
			depsChan = make(chan depResult, 1)
			go func(ctx context.Context, b *EntBackend, sbomID string, first int, artChan chan<- depResult) {
				var afterCursor *entgql.Cursor[uuid.UUID]
				defer close(depsChan)
				for {
					isDepQuery := b.client.Dependency.Query().
						Where(dependency.HasIncludedInSbomsWith([]predicate.BillOfMaterials{
							optionalPredicate(&sbomID, IDEQ)}...))

					depConnect, err := getIsDepObject(isDepQuery).
						Paginate(ctx, afterCursor, &first, nil, nil)
					if err != nil {
						depsChan <- depResult{deps: nil,
							depErr: fmt.Errorf("failed included dependency query for hasSBOM with error: %w", err)}
					}

					// if not found break
					if depConnect == nil {
						break
					}

					var paginatedDeps []*ent.Dependency
					for _, edge := range depConnect.Edges {
						paginatedDeps = append(paginatedDeps, edge.Node)
					}

					depsChan <- depResult{deps: paginatedDeps,
						depErr: nil}

					if !depConnect.PageInfo.HasNextPage {
						break
					}
					afterCursor = depConnect.PageInfo.EndCursor
				}
			}(ctx, b, sbomID, includedFirst, depsChan)
		}

		// query included occurrences
		if outputIncludedOccurrences {
			occursChan = make(chan occurResult, 1)
			go func(ctx context.Context, b *EntBackend, sbomID string, first int, occursChan chan<- occurResult) {
				var afterCursor *entgql.Cursor[uuid.UUID]
				defer close(occursChan)
				for {
					occurQuery := b.client.Occurrence.Query().
						Where(occurrence.HasIncludedInSbomsWith([]predicate.BillOfMaterials{
							optionalPredicate(&sbomID, IDEQ)}...))

					occurConnect, err := getOccurrenceObject(occurQuery).
						Paginate(ctx, afterCursor, &first, nil, nil)
					if err != nil {
						occursChan <- occurResult{occurs: nil,
							occurErr: fmt.Errorf("failed included occurrence query for hasSBOM with error: %w", err)}
					}

					// if not found break
					if occurConnect == nil {
						break
					}

					var paginatedOccurs []*ent.Occurrence
					for _, edge := range occurConnect.Edges {
						paginatedOccurs = append(paginatedOccurs, edge.Node)
					}

					occursChan <- occurResult{occurs: paginatedOccurs,
						occurErr: nil}

					if !occurConnect.PageInfo.HasNextPage {
						break
					}
					afterCursor = occurConnect.PageInfo.EndCursor
				}
			}(ctx, b, sbomID, includedFirst, occursChan)
		}

		if artChan != nil {
			for art := range artChan {
				if art.artErr != nil {
					return nil, fmt.Errorf("artifact channel failure: %w", art.artErr)
				}
				includedArtifacts = append(includedArtifacts, art.arts...)
			}
		}

		if pkgVerChan != nil {
			for pkg := range pkgVerChan {
				if pkg.pkgVerErr != nil {
					return nil, fmt.Errorf("pkgVersion channel failure: %w", pkg.pkgVerErr)
				}
				includedPackages = append(includedPackages, pkg.pkgVersions...)
			}
		}

		if occursChan != nil {
			for occur := range occursChan {
				if occur.occurErr != nil {
					return nil, fmt.Errorf("occurrence channel failure: %w", occur.occurErr)
				}
				includedOccurs = append(includedOccurs, occur.occurs...)
			}
		}

		if depsChan != nil {
			for dep := range depsChan {
				if dep.depErr != nil {
					return nil, fmt.Errorf("dependency channel failure: %w", dep.depErr)
				}
				includedDeps = append(includedDeps, dep.deps...)
			}
		}

		reconstructedSBOM := toModelHasSBOMWithIncluded(foundSBOM.Node, includedPackages, includedArtifacts, includedDeps, includedOccurs)
		reconstructedSBOMs[sbomID] = reconstructedSBOM
	}

	var edges []*model.HasSBOMEdge
	for id, edge := range reconstructedSBOMs {
		edges = append(edges, &model.HasSBOMEdge{
			Cursor: hasSBOMGlobalID(id),
			Node:   edge,
		})
	}

	if hasSBOMConnection.PageInfo.StartCursor != nil {
		return &model.HasSBOMConnection{
			TotalCount: hasSBOMConnection.TotalCount,
			PageInfo: &model.PageInfo{
				HasNextPage: hasSBOMConnection.PageInfo.HasNextPage,
				StartCursor: ptrfrom.String(hasSBOMGlobalID(hasSBOMConnection.PageInfo.StartCursor.ID.String())),
				EndCursor:   ptrfrom.String(hasSBOMGlobalID(hasSBOMConnection.PageInfo.EndCursor.ID.String())),
			},
			Edges: edges,
		}, nil
	} else {
		// if not found return nil
		return nil, nil
	}
}

func (b *EntBackend) HasSBOM(ctx context.Context, spec *model.HasSBOMSpec) ([]*model.HasSbom, error) {
	funcName := "HasSBOM"
	if spec == nil {
		spec = &model.HasSBOMSpec{}
	}

	sbomQuery := b.client.BillOfMaterials.Query().
		Where(hasSBOMQuery(*spec))

	records, err := getSBOMObjectWithIncludes(sbomQuery).
		All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, funcName)
	}

	return collect(records, toModelHasSBOM), nil
}

func hasSBOMQuery(spec model.HasSBOMSpec) predicate.BillOfMaterials {
	predicates := []predicate.BillOfMaterials{
		optionalPredicate(spec.ID, IDEQ),
		optionalPredicate(toLowerPtr(spec.Algorithm), billofmaterials.AlgorithmEQ),
		optionalPredicate(toLowerPtr(spec.Digest), billofmaterials.DigestEQ),
		optionalPredicate(spec.URI, billofmaterials.URI),
		optionalPredicate(spec.Collector, billofmaterials.CollectorEQ),
		optionalPredicate(spec.DownloadLocation, billofmaterials.DownloadLocationEQ),
		optionalPredicate(spec.Origin, billofmaterials.OriginEQ),
		optionalPredicate(spec.KnownSince, billofmaterials.KnownSinceEQ),
		optionalPredicate(spec.DocumentRef, billofmaterials.DocumentRefEQ),
	}

	if spec.Subject != nil {
		if spec.Subject.Package != nil {
			if spec.Subject.Package.ID != nil {
				predicates = append(predicates, optionalPredicate(spec.Subject.Package.ID, packageIDEQ))
				predicates = append(predicates, billofmaterials.ArtifactIDIsNil())
			} else {
				predicates = append(predicates,
					billofmaterials.HasPackageWith(packageVersionQuery(spec.Subject.Package)))
			}
		} else if spec.Subject.Artifact != nil {
			if spec.Subject.Artifact.ID != nil {
				predicates = append(predicates,
					optionalPredicate(spec.Subject.Artifact.ID, artifactIDEQ))
				predicates = append(predicates, billofmaterials.PackageIDIsNil())
			} else {
				predicates = append(predicates,
					billofmaterials.HasArtifactWith(artifactQueryPredicates(spec.Subject.Artifact)))
			}
		}
	}

	for i := range spec.IncludedSoftware {
		if spec.IncludedSoftware[i].Package != nil {
			predicates = append(predicates, billofmaterials.HasIncludedSoftwarePackagesWith(packageVersionQuery(spec.IncludedSoftware[i].Package)))
		} else {
			predicates = append(predicates, billofmaterials.HasIncludedSoftwareArtifactsWith(artifactQueryPredicates(spec.IncludedSoftware[i].Artifact)))
		}
	}
	for i := range spec.IncludedDependencies {
		predicates = append(predicates, billofmaterials.HasIncludedDependenciesWith(isDependencyQuery(spec.IncludedDependencies[i])))
	}
	for i := range spec.IncludedOccurrences {
		predicates = append(predicates, billofmaterials.HasIncludedOccurrencesWith(isOccurrenceQuery(spec.IncludedOccurrences[i])))
	}
	return billofmaterials.And(predicates...)
}

// getSBOMObjectWithOutIncludes is used recreate the hasSBOM object without eager loading the included edges
func getSBOMObjectWithOutIncludes(q *ent.BillOfMaterialsQuery) *ent.BillOfMaterialsQuery {
	return q.
		WithPackage(func(q *ent.PackageVersionQuery) {
			q.WithName(func(q *ent.PackageNameQuery) {})
		}).
		WithArtifact()
}

// getSBOMObjectWithIncludes is used recreate the hasSBOM object be eager loading the edges
func getSBOMObjectWithIncludes(q *ent.BillOfMaterialsQuery) *ent.BillOfMaterialsQuery {
	return q.
		WithPackage(func(q *ent.PackageVersionQuery) {
			q.WithName(func(q *ent.PackageNameQuery) {})
		}).
		WithArtifact().
		WithIncludedSoftwareArtifacts().
		WithIncludedSoftwarePackages(withPackageVersionTree()).
		WithIncludedDependencies(func(q *ent.DependencyQuery) {
			q.WithPackage(withPackageVersionTree()).
				WithDependentPackageVersion(withPackageVersionTree())
		}).
		WithIncludedOccurrences(func(q *ent.OccurrenceQuery) {
			q.WithArtifact().
				WithPackage(withPackageVersionTree()).
				WithSource(withSourceNameTreeQuery())
		})
}

func (b *EntBackend) deleteHasSbom(ctx context.Context, hasSBOMID uuid.UUID) (bool, error) {
	_, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		tx := ent.TxFromContext(ctx)

		// first delete isDependency and isOccurrence nodes that are part of the hasSBOM node
		if err := b.deleteIsDependency(ctx, hasSBOMID.String()); err != nil {
			return nil, fmt.Errorf("failed to delete isDependency with error: %w", err)
		}

		if err := b.deleteIsOccurrences(ctx, hasSBOMID.String()); err != nil {
			return nil, fmt.Errorf("failed to delete isOccurrence with error: %w", err)
		}

		// delete hasSBOM node
		if err := tx.BillOfMaterials.DeleteOneID(hasSBOMID).Exec(ctx); err != nil {
			return nil, errors.Wrap(err, "failed to delete hasSBOM with error")
		}
		return nil, nil
	})
	if txErr != nil {
		return false, txErr
	}
	return true, nil
}

func (b *EntBackend) IngestHasSbom(ctx context.Context, subject model.PackageOrArtifactInput, spec model.HasSBOMInputSpec, includes model.HasSBOMIncludesInputSpec) (string, error) {
	funcName := "IngestHasSbom"

	sbomId, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		tx := ent.TxFromContext(ctx)

		id, err := upsertHasSBOM(ctx, tx, subject, spec, includes)
		if err != nil {
			return nil, gqlerror.Errorf("generateSBOMCreate :: %s", err)
		}

		return id, nil
	})
	if txErr != nil {
		return "", Errorf("%v :: %s", funcName, txErr)
	}

	return hasSBOMGlobalID(*sbomId), nil
}

func (b *EntBackend) IngestHasSBOMs(ctx context.Context, subjects model.PackageOrArtifactInputs, hasSBOMs []*model.HasSBOMInputSpec, includes []*model.HasSBOMIncludesInputSpec) ([]string, error) {
	funcName := "IngestHasSBOMs"
	ids, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		hsl, err := upsertBulkSBOM(ctx, client, subjects, hasSBOMs, includes)
		if err != nil {
			return nil, err
		}
		return hsl, nil
	})
	if txErr != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, txErr)
	}

	return bulkHasSBOMGlobalID(*ids), nil
}

func sbomConflictColumns() []string {
	return []string{
		billofmaterials.FieldURI,
		billofmaterials.FieldAlgorithm,
		billofmaterials.FieldDigest,
		billofmaterials.FieldDownloadLocation,
		billofmaterials.FieldKnownSince,
		billofmaterials.FieldIncludedPackagesHash,
		billofmaterials.FieldIncludedArtifactsHash,
		billofmaterials.FieldIncludedDependenciesHash,
		billofmaterials.FieldIncludedOccurrencesHash,
		billofmaterials.FieldCollector,
		billofmaterials.FieldOrigin,
		billofmaterials.FieldDocumentRef,
	}
}

func upsertBulkSBOM(ctx context.Context, tx *ent.Tx, subjects model.PackageOrArtifactInputs, hasSBOMs []*model.HasSBOMInputSpec, includes []*model.HasSBOMIncludesInputSpec) (*[]string, error) {
	ids := make([]string, 0)

	conflictColumns := sbomConflictColumns()
	var conflictWhere *sql.Predicate

	switch {
	case len(subjects.Artifacts) > 0:
		conflictColumns = append(conflictColumns, billofmaterials.FieldArtifactID)
		conflictWhere = sql.And(
			sql.IsNull(billofmaterials.FieldPackageID),
			sql.NotNull(billofmaterials.FieldArtifactID),
		)
	case len(subjects.Packages) > 0:
		conflictColumns = append(conflictColumns, billofmaterials.FieldPackageID)
		conflictWhere = sql.And(
			sql.NotNull(billofmaterials.FieldPackageID),
			sql.IsNull(billofmaterials.FieldArtifactID),
		)
	}

	var listOfSBOMIDs []uuid.UUID
	withIncludePackageIDs := make(map[uuid.UUID][]uuid.UUID)
	withIncludeArtifactsIDs := make(map[uuid.UUID][]uuid.UUID)
	withIncludeDependencyIDs := make(map[uuid.UUID][]uuid.UUID)
	withIncludeOccurrenceIDs := make(map[uuid.UUID][]uuid.UUID)

	batches := chunk(hasSBOMs, MaxBatchSize)

	index := 0
	for _, hss := range batches {
		creates := make([]*ent.BillOfMaterialsCreate, len(hss))
		for i, sbom := range hss {
			sbom := sbom
			var err error

			sortedPkgIDs := helper.SortAndRemoveDups(includes[index].Packages)
			sortedArtIDs := helper.SortAndRemoveDups(includes[index].Artifacts)
			sortedDependencyIDs := helper.SortAndRemoveDups(includes[index].Dependencies)
			sortedOccurrenceIDs := helper.SortAndRemoveDups(includes[index].Occurrences)

			var sortedPkgUUIDs []uuid.UUID
			var sortedArtUUIDs []uuid.UUID
			var sortedIsDepUUIDs []uuid.UUID
			var sortedIsOccurrenceUUIDs []uuid.UUID

			for _, pkgID := range sortedPkgIDs {
				pkgGlobalID := fromGlobalID(pkgID)
				pkgIncludesID, err := uuid.Parse(pkgGlobalID.id)
				if err != nil {
					return nil, fmt.Errorf("uuid conversion from packageVersionID failed with error: %w", err)
				}
				sortedPkgUUIDs = append(sortedPkgUUIDs, pkgIncludesID)
			}

			for _, artID := range sortedArtIDs {
				artGlobalID := fromGlobalID(artID)
				artIncludesID, err := uuid.Parse(artGlobalID.id)
				if err != nil {
					return nil, fmt.Errorf("uuid conversion from ArtifactID failed with error: %w", err)
				}
				sortedArtUUIDs = append(sortedArtUUIDs, artIncludesID)
			}

			for _, isDependencyID := range sortedDependencyIDs {
				depGlobalID := fromGlobalID(isDependencyID)
				isDepIncludesID, err := uuid.Parse(depGlobalID.id)
				if err != nil {
					return nil, fmt.Errorf("uuid conversion from isDependencyID failed with error: %w", err)
				}
				sortedIsDepUUIDs = append(sortedIsDepUUIDs, isDepIncludesID)
			}

			for _, isOccurrenceID := range sortedOccurrenceIDs {
				occurGlobalID := fromGlobalID(isOccurrenceID)
				isOccurIncludesID, err := uuid.Parse(occurGlobalID.id)
				if err != nil {
					return nil, fmt.Errorf("uuid conversion from isOccurrenceID failed with error: %w", err)
				}
				sortedIsOccurrenceUUIDs = append(sortedIsOccurrenceUUIDs, isOccurIncludesID)
			}

			switch {
			case len(subjects.Artifacts) > 0:
				creates[i], err = generateSBOMCreate(ctx, tx, nil, subjects.Artifacts[index], sortedPkgIDs, sortedArtIDs,
					sortedDependencyIDs, sortedOccurrenceIDs, sbom)
				if err != nil {
					return nil, gqlerror.Errorf("generateSBOMCreate :: %s", err)
				}
			case len(subjects.Packages) > 0:
				creates[i], err = generateSBOMCreate(ctx, tx, subjects.Packages[index], nil, sortedPkgIDs, sortedArtIDs,
					sortedDependencyIDs, sortedOccurrenceIDs, sbom)
				if err != nil {
					return nil, gqlerror.Errorf("generateSBOMCreate :: %s", err)
				}
			}

			if hasSBOMNodeID, exist := creates[i].Mutation().ID(); exist {
				listOfSBOMIDs = append(listOfSBOMIDs, hasSBOMNodeID)
				withIncludePackageIDs[hasSBOMNodeID] = sortedPkgUUIDs
				withIncludeArtifactsIDs[hasSBOMNodeID] = sortedArtUUIDs
				withIncludeDependencyIDs[hasSBOMNodeID] = sortedIsDepUUIDs
				withIncludeOccurrenceIDs[hasSBOMNodeID] = sortedIsOccurrenceUUIDs
			} else {
				return nil, fmt.Errorf("failed to get hasSBOM ID to attach includes")
			}
			index++
		}

		err := tx.BillOfMaterials.CreateBulk(creates...).
			OnConflict(
				sql.ConflictColumns(conflictColumns...),
				sql.ConflictWhere(conflictWhere),
			).
			DoNothing().
			Exec(ctx)
		if err != nil && err != stdsql.ErrNoRows {
			// err "no rows in select set" appear when ingesting and the node already exists. This is non-error produced by "DoNothing"
			return nil, errors.Wrap(err, "upsert hasSBOM node")
		}

		for _, id := range listOfSBOMIDs {
			if err := updateHasSBOMWithIncludePackageIDs(ctx, tx.Client(), id, withIncludePackageIDs[id]); err != nil {
				return nil, errors.Wrap(err, "updateHasSBOMWithIncludePackageIDs")
			}

			if err := updateHasSBOMWithIncludeArtifacts(ctx, tx.Client(), id, withIncludeArtifactsIDs[id]); err != nil {
				return nil, errors.Wrap(err, "updateHasSBOMWithIncludeArtifacts")
			}

			if err := updateHasSBOMWithIncludeDependencies(ctx, tx.Client(), id, withIncludeDependencyIDs[id]); err != nil {
				return nil, errors.Wrap(err, "updateHasSBOMWithIncludeDependencies")
			}

			if err := updateHasSBOMWithIncludeOccurrences(ctx, tx.Client(), id, withIncludeOccurrenceIDs[id]); err != nil {
				return nil, errors.Wrap(err, "updateHasSBOMWithIncludeOccurrences")
			}
			ids = append(ids, id.String())
		}
	}
	return &ids, nil
}

func upsertHasSBOM(ctx context.Context, tx *ent.Tx, subject model.PackageOrArtifactInput, spec model.HasSBOMInputSpec, includes model.HasSBOMIncludesInputSpec) (*string, error) {

	// If a new column is included in the conflict columns, it must be added to the Indexes() function in the schema
	conflictColumns := sbomConflictColumns()

	var conflictWhere *sql.Predicate

	if subject.Package != nil {
		conflictColumns = append(conflictColumns, billofmaterials.FieldPackageID)
		conflictWhere = sql.And(
			sql.NotNull(billofmaterials.FieldPackageID),
			sql.IsNull(billofmaterials.FieldArtifactID),
		)
	} else if subject.Artifact != nil {
		conflictColumns = append(conflictColumns, billofmaterials.FieldArtifactID)
		conflictWhere = sql.And(
			sql.IsNull(billofmaterials.FieldPackageID),
			sql.NotNull(billofmaterials.FieldArtifactID),
		)
	} else {
		return nil, Errorf("%v :: %s", "upsertHasSBOM", "subject must be either a package or artifact")
	}

	sortedPkgIDs := helper.SortAndRemoveDups(includes.Packages)
	sortedArtIDs := helper.SortAndRemoveDups(includes.Artifacts)
	sortedDependencyIDs := helper.SortAndRemoveDups(includes.Dependencies)
	sortedOccurrenceIDs := helper.SortAndRemoveDups(includes.Occurrences)

	var sortedPkgUUIDs []uuid.UUID
	var sortedArtUUIDs []uuid.UUID
	var sortedIsDepUUIDs []uuid.UUID
	var sortedIsOccurrenceUUIDs []uuid.UUID

	for _, pkgID := range sortedPkgIDs {
		pkgGlobalID := fromGlobalID(pkgID)
		pkgIncludesID, err := uuid.Parse(pkgGlobalID.id)
		if err != nil {
			return nil, fmt.Errorf("uuid conversion from packageVersionID failed with error: %w", err)
		}
		sortedPkgUUIDs = append(sortedPkgUUIDs, pkgIncludesID)
	}

	for _, artID := range sortedArtIDs {
		artGlobalID := fromGlobalID(artID)
		artIncludesID, err := uuid.Parse(artGlobalID.id)
		if err != nil {
			return nil, fmt.Errorf("uuid conversion from ArtifactID failed with error: %w", err)
		}
		sortedArtUUIDs = append(sortedArtUUIDs, artIncludesID)
	}

	for _, isDependencyID := range sortedDependencyIDs {
		depGlobalID := fromGlobalID(isDependencyID)
		isDepIncludesID, err := uuid.Parse(depGlobalID.id)
		if err != nil {
			return nil, fmt.Errorf("uuid conversion from isDependencyID failed with error: %w", err)
		}
		sortedIsDepUUIDs = append(sortedIsDepUUIDs, isDepIncludesID)
	}

	for _, isOccurrenceID := range sortedOccurrenceIDs {
		occurGlobalID := fromGlobalID(isOccurrenceID)
		isOccurIncludesID, err := uuid.Parse(occurGlobalID.id)
		if err != nil {
			return nil, fmt.Errorf("uuid conversion from isOccurrenceID failed with error: %w", err)
		}
		sortedIsOccurrenceUUIDs = append(sortedIsOccurrenceUUIDs, isOccurIncludesID)
	}

	sbomCreate, err := generateSBOMCreate(ctx, tx, subject.Package, subject.Artifact, sortedPkgIDs, sortedArtIDs,
		sortedDependencyIDs, sortedOccurrenceIDs, &spec)
	if err != nil {
		return nil, gqlerror.Errorf("generateSLSACreate :: %s", err)
	}

	if _, err := sbomCreate.
		OnConflict(
			sql.ConflictColumns(conflictColumns...),
			sql.ConflictWhere(conflictWhere),
		).
		DoNothing().
		ID(ctx); err != nil {
		// err "no rows in select set" appear when ingesting and the node already exists. This is non-error produced by "DoNothing"
		if err != stdsql.ErrNoRows {
			return nil, errors.Wrap(err, "upsert hasSBOM node")
		}
	}

	var id uuid.UUID
	if hasSBOMNodeID, exist := sbomCreate.Mutation().ID(); exist {
		id = hasSBOMNodeID
	} else {
		return nil, fmt.Errorf("failed to get hasSBOM ID to attach includes")
	}

	if err := updateHasSBOMWithIncludePackageIDs(ctx, tx.Client(), id, sortedPkgUUIDs); err != nil {
		return nil, errors.Wrap(err, "updateHasSBOMWithIncludePackageIDs")
	}

	if err := updateHasSBOMWithIncludeArtifacts(ctx, tx.Client(), id, sortedArtUUIDs); err != nil {
		return nil, errors.Wrap(err, "updateHasSBOMWithIncludeArtifacts")
	}

	if err := updateHasSBOMWithIncludeDependencies(ctx, tx.Client(), id, sortedIsDepUUIDs); err != nil {
		return nil, errors.Wrap(err, "updateHasSBOMWithIncludeDependencies")
	}

	if err := updateHasSBOMWithIncludeOccurrences(ctx, tx.Client(), id, sortedIsOccurrenceUUIDs); err != nil {
		return nil, errors.Wrap(err, "updateHasSBOMWithIncludeOccurrences")
	}

	return ptrfrom.String(id.String()), nil
}

func generateSBOMCreate(ctx context.Context, tx *ent.Tx, pkg *model.IDorPkgInput, art *model.IDorArtifactInput, sortedPkgIDs,
	sortedArtIDs, sortedDependencyIDs, sortedOccurrenceIDs []string, hasSBOM *model.HasSBOMInputSpec) (*ent.BillOfMaterialsCreate, error) {

	sbomCreate := tx.BillOfMaterials.Create().
		SetURI(hasSBOM.URI).
		SetAlgorithm(strings.ToLower(hasSBOM.Algorithm)).
		SetDigest(strings.ToLower(hasSBOM.Digest)).
		SetDownloadLocation(hasSBOM.DownloadLocation).
		SetOrigin(hasSBOM.Origin).
		SetCollector(hasSBOM.Collector).
		SetDocumentRef(hasSBOM.DocumentRef).
		SetKnownSince(hasSBOM.KnownSince.UTC())

	var sortedPkgHash string
	var sortedArtHash string
	var sortedDepHash string
	var sortedOccurHash string

	if len(sortedPkgIDs) > 0 {
		sortedPkgHash = hashListOfSortedKeys(sortedPkgIDs)
		sbomCreate.SetIncludedPackagesHash(sortedPkgHash)
	} else {
		sortedPkgHash = hashListOfSortedKeys([]string{""})
		sbomCreate.SetIncludedPackagesHash(sortedPkgHash)
	}

	if len(sortedArtIDs) > 0 {
		sortedArtHash = hashListOfSortedKeys(sortedArtIDs)
		sbomCreate.SetIncludedArtifactsHash(sortedArtHash)
	} else {
		sortedArtHash = hashListOfSortedKeys([]string{""})
		sbomCreate.SetIncludedArtifactsHash(sortedArtHash)
	}

	if len(sortedDependencyIDs) > 0 {
		sortedDepHash = hashListOfSortedKeys(sortedDependencyIDs)
		sbomCreate.SetIncludedDependenciesHash(sortedDepHash)
	} else {
		sortedDepHash = hashListOfSortedKeys([]string{""})
		sbomCreate.SetIncludedDependenciesHash(sortedDepHash)
	}

	if len(sortedOccurrenceIDs) > 0 {
		sortedOccurHash = hashListOfSortedKeys(sortedOccurrenceIDs)
		sbomCreate.SetIncludedOccurrencesHash(sortedOccurHash)
	} else {
		sortedOccurHash = hashListOfSortedKeys([]string{""})
		sbomCreate.SetIncludedOccurrencesHash(sortedOccurHash)
	}

	if pkg != nil {
		var pkgVersionID uuid.UUID
		if pkg.PackageVersionID != nil {
			var err error
			pkgVersionGlobalID := fromGlobalID(*pkg.PackageVersionID)
			pkgVersionID, err = uuid.Parse(pkgVersionGlobalID.id)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from packageVersionID failed with error: %w", err)
			}
		} else {
			pv, err := getPkgVersion(ctx, tx.Client(), *pkg.PackageInput)
			if err != nil {
				return nil, fmt.Errorf("getPkgVersion :: %w", err)
			}
			pkgVersionID = pv.ID
		}
		hasSBOMID, err := guacHasSBOMKey(ptrfrom.String(pkgVersionID.String()), nil, sortedPkgHash, sortedArtHash, sortedDepHash, sortedOccurHash, hasSBOM)
		if err != nil {
			return nil, fmt.Errorf("failed to create hasSBOM uuid with error: %w", err)
		}
		sbomCreate.SetID(*hasSBOMID)
		sbomCreate.SetPackageID(pkgVersionID)
	} else if art != nil {
		var artID uuid.UUID
		if art.ArtifactID != nil {
			var err error
			artGlobalID := fromGlobalID(*art.ArtifactID)
			artID, err = uuid.Parse(artGlobalID.id)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from ArtifactID failed with error: %w", err)
			}
		} else {
			foundArt, err := tx.Artifact.Query().Where(artifactQueryInputPredicates(*art.ArtifactInput)).Only(ctx)
			if err != nil {
				return nil, err
			}
			artID = foundArt.ID
		}
		hasSBOMID, err := guacHasSBOMKey(nil, ptrfrom.String(artID.String()), sortedPkgHash, sortedArtHash, sortedDepHash, sortedOccurHash, hasSBOM)
		if err != nil {
			return nil, fmt.Errorf("failed to create hasSBOM uuid with error: %w", err)
		}
		sbomCreate.SetID(*hasSBOMID)
		sbomCreate.SetArtifactID(artID)
	} else {
		return nil, Errorf("%v :: %s", "generateSBOMCreate", "subject must be either a package or artifact")
	}

	return sbomCreate, nil
}

func updateHasSBOMWithIncludePackageIDs(ctx context.Context, client *ent.Client, hasSBOMID uuid.UUID, sortedPkgUUIDs []uuid.UUID) error {
	batches := chunk(sortedPkgUUIDs, 10000)

	for _, batchedPkgUUIDs := range batches {
		err := client.BillOfMaterials.
			UpdateOneID(hasSBOMID).
			AddIncludedSoftwarePackageIDs(batchedPkgUUIDs...).
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("update for IncludedSoftwarePackageIDs hasSBOM node failed with error: %w", err)
		}
	}
	return nil
}

func updateHasSBOMWithIncludeArtifacts(ctx context.Context, client *ent.Client, hasSBOMID uuid.UUID, sortedArtUUIDs []uuid.UUID) error {
	batches := chunk(sortedArtUUIDs, 10000)

	for _, batchedArtUUIDs := range batches {
		err := client.BillOfMaterials.
			UpdateOneID(hasSBOMID).
			AddIncludedSoftwareArtifactIDs(batchedArtUUIDs...).
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("update for IncludedSoftwareArtifactIDs hasSBOM node failed with error: %w", err)
		}
	}
	return nil
}

func updateHasSBOMWithIncludeDependencies(ctx context.Context, client *ent.Client, hasSBOMID uuid.UUID, sortedIsDepUUIDs []uuid.UUID) error {
	batches := chunk(sortedIsDepUUIDs, 10000)

	for _, batchedIsDepUUIDs := range batches {
		err := client.BillOfMaterials.
			UpdateOneID(hasSBOMID).
			AddIncludedDependencyIDs(batchedIsDepUUIDs...).
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("update for IncludedDependencyIDs hasSBOM node failed with error: %w", err)
		}
	}
	return nil
}

func updateHasSBOMWithIncludeOccurrences(ctx context.Context, client *ent.Client, hasSBOMID uuid.UUID, sortedIsOccurrenceUUIDs []uuid.UUID) error {
	batches := chunk(sortedIsOccurrenceUUIDs, 10000)

	for _, batchedIsOccurUUIDs := range batches {
		err := client.BillOfMaterials.
			UpdateOneID(hasSBOMID).
			AddIncludedOccurrenceIDs(batchedIsOccurUUIDs...).
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("update for IncludedOccurrenceIDs hasSBOM node failed with error: %w", err)
		}
	}
	return nil
}

func canonicalHasSBOMString(hasSBOM *model.HasSBOMInputSpec) string {
	return fmt.Sprintf("%s::%s::%s::%s::%s::%s::%s:%s", hasSBOM.URI, hasSBOM.Algorithm, hasSBOM.Digest, hasSBOM.DownloadLocation, hasSBOM.Origin, hasSBOM.Collector, hasSBOM.KnownSince.UTC(), hasSBOM.DocumentRef)
}

// guacHasSBOMKey generates an uuid based on the hash of the inputspec and inputs. hasSBOM ID has to be set for bulk ingestion
// when ingesting multiple edges otherwise you get "violates foreign key constraint" as it creates
// a new ID for hasSBOM node (even when already ingested) that it maps to the edge and fails the look up. This only occurs when using UUID with
// "Default" func to generate a new UUID
func guacHasSBOMKey(pkgVersionID *string, artID *string, includedPkgHash, includedArtHash, includedDepHash, includedOccurHash string,
	hasSBOM *model.HasSBOMInputSpec) (*uuid.UUID, error) {

	var subjectID string
	if pkgVersionID != nil {
		subjectID = *pkgVersionID
	} else if artID != nil {
		subjectID = *artID
	} else {
		return nil, gqlerror.Errorf("%v :: %s", "guacHasSBOMKey", "subject must be either a package or artifact")
	}
	hsIDString := fmt.Sprintf("%s::%s::%s::%s::%s::%s?", subjectID, includedPkgHash, includedArtHash, includedDepHash, includedOccurHash, canonicalHasSBOMString(hasSBOM))

	hsID := generateUUIDKey([]byte(hsIDString))
	return &hsID, nil
}

func (b *EntBackend) hasSbomNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]model.Node, error) {
	var out []model.Node

	query := b.client.BillOfMaterials.Query().
		Where(hasSBOMQuery(model.HasSBOMSpec{ID: &nodeID}))

	if allowedEdges[model.EdgeHasSbomPackage] {
		query.
			WithPackage(withPackageVersionTree())
	}
	if allowedEdges[model.EdgeHasSbomArtifact] {
		query.
			WithArtifact()
	}
	if allowedEdges[model.EdgeHasSbomIncludedSoftware] {
		query.
			WithIncludedSoftwarePackages(withPackageVersionTree()).
			WithIncludedSoftwareArtifacts()
	}

	if allowedEdges[model.EdgeHasSbomIncludedDependencies] {
		query.
			WithIncludedDependencies(func(q *ent.DependencyQuery) {
				getIsDepObject(q)
			})
	}
	if allowedEdges[model.EdgeHasSbomIncludedOccurrences] {
		query.
			WithIncludedOccurrences(func(q *ent.OccurrenceQuery) {
				getOccurrenceObject(q)
			})
	}

	bills, err := query.All(ctx)
	if err != nil {
		return []model.Node{}, fmt.Errorf("failed query hasSBOM with node ID: %s with error: %w", nodeID, err)
	}

	for _, bill := range bills {
		if bill.Edges.Package != nil {
			out = append(out, toModelPackage(backReferencePackageVersion(bill.Edges.Package)))
		}
		if bill.Edges.Artifact != nil {
			out = append(out, toModelArtifact(bill.Edges.Artifact))
		}
		if len(bill.Edges.IncludedSoftwareArtifacts) > 0 {
			for _, includedArt := range bill.Edges.IncludedSoftwareArtifacts {
				out = append(out, toModelArtifact(includedArt))
			}
		}
		if len(bill.Edges.IncludedSoftwarePackages) > 0 {
			for _, includedPkg := range bill.Edges.IncludedSoftwarePackages {
				out = append(out, toModelPackage(backReferencePackageVersion(includedPkg)))
			}
		}
		if len(bill.Edges.IncludedDependencies) > 0 {
			for _, includedDep := range bill.Edges.IncludedDependencies {
				out = append(out, toModelIsDependencyWithBackrefs(includedDep))
			}
		}
		if len(bill.Edges.IncludedOccurrences) > 0 {
			for _, includedOccur := range bill.Edges.IncludedOccurrences {
				out = append(out, toModelIsOccurrenceWithSubject(includedOccur))
			}
		}
	}

	return out, nil
}
