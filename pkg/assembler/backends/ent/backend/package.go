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
	"bytes"
	"context"
	"crypto/sha1"
	stdsql "database/sql"
	"fmt"
	"sort"
	"strings"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certification"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/pkg/errors"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

const (
	pkgTypeString      = "package_types"
	pkgNamespaceString = "package_namespaces"
)

func (b *EntBackend) PackagesList(ctx context.Context, pkgSpec model.PkgSpec, after *string, first *int) (*model.PackageConnection, error) {
	return nil, fmt.Errorf("not implemented: PackagesList")
}

func (b *EntBackend) Packages(ctx context.Context, pkgSpec *model.PkgSpec) ([]*model.Package, error) {
	if pkgSpec == nil {
		pkgSpec = &model.PkgSpec{}
	}

	pkgs, err := b.client.PackageVersion.Query().
		Where(packageQueryPredicates(pkgSpec)).
		WithName(func(q *ent.PackageNameQuery) {}).
		Limit(MaxPageSize).
		All(ctx)
	if err != nil {
		return nil, err
	}

	var pkgNames []*ent.PackageName
	for _, collectedPkgVersion := range pkgs {
		pkgNames = append(pkgNames, backReferencePackageVersion(collectedPkgVersion))
	}

	return toModelPackageTrie(pkgNames), nil
}

func packageQueryPredicates(pkgSpec *model.PkgSpec) predicate.PackageVersion {
	return packageversion.And(
		optionalPredicate(pkgSpec.ID, IDEQ),
		optionalPredicate(pkgSpec.Version, packageversion.VersionEqualFold),
		optionalPredicate(pkgSpec.Subpath, packageversion.SubpathEqualFold),
		packageversion.QualifiersMatch(pkgSpec.Qualifiers, ptrWithDefault(pkgSpec.MatchOnlyEmptyQualifiers, false)),
		packageversion.HasNameWith(
			optionalPredicate(pkgSpec.Type, packagename.TypeEQ),
			optionalPredicate(pkgSpec.Namespace, packagename.NamespaceEQ),
			optionalPredicate(pkgSpec.Name, packagename.NameEQ),
		),
	)
}

func (b *EntBackend) IngestPackages(ctx context.Context, pkgs []*model.IDorPkgInput) ([]*model.PackageIDs, error) {
	funcName := "IngestPackages"
	var collectedPkgIDs []*model.PackageIDs
	ids, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*[]model.PackageIDs, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkPackage(ctx, client, pkgs)
		if err != nil {
			return nil, err
		}
		return slc, nil
	})
	if txErr != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, txErr)
	}

	for _, pkgIDs := range *ids {
		p := pkgIDs
		collectedPkgIDs = append(collectedPkgIDs, &p)
	}

	return collectedPkgIDs, nil
}

func (b *EntBackend) IngestPackage(ctx context.Context, pkg model.IDorPkgInput) (*model.PackageIDs, error) {
	pkgVersionID, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*model.PackageIDs, error) {
		p, err := upsertPackage(ctx, ent.TxFromContext(ctx), pkg)
		if err != nil {
			return nil, errors.Wrap(err, "failed to upsert package")
		}
		return p, nil
	})
	if txErr != nil {
		return nil, txErr
	}

	return pkgVersionID, nil
}

func generatePackageNameCreate(tx *ent.Tx, pkgNameID *uuid.UUID, pkgInput *model.IDorPkgInput) *ent.PackageNameCreate {
	return tx.PackageName.Create().
		SetID(*pkgNameID).
		SetType(pkgInput.PackageInput.Type).
		SetNamespace(stringOrEmpty(pkgInput.PackageInput.Namespace)).
		SetName(pkgInput.PackageInput.Name)
}

func generatePackageVersionCreate(tx *ent.Tx, pkgVersionID *uuid.UUID, pkgNameID *uuid.UUID, pkgInput *model.IDorPkgInput) *ent.PackageVersionCreate {
	return tx.PackageVersion.Create().
		SetID(*pkgVersionID).
		SetNameID(*pkgNameID).
		SetNillableVersion(pkgInput.PackageInput.Version).
		SetSubpath(ptrWithDefault(pkgInput.PackageInput.Subpath, "")).
		SetQualifiers(normalizeInputQualifiers(pkgInput.PackageInput.Qualifiers)).
		SetHash(versionHashFromInputSpec(*pkgInput.PackageInput))
}

func upsertBulkPackage(ctx context.Context, tx *ent.Tx, pkgInputs []*model.IDorPkgInput) (*[]model.PackageIDs, error) {
	batches := chunk(pkgInputs, MaxBatchSize)
	pkgNameIDs := make([]string, 0)
	pkgVersionIDs := make([]string, 0)
	pkgTypes := map[string]string{}
	pkgNamespaces := map[string]string{}

	for _, pkgs := range batches {
		pkgNameCreates := make([]*ent.PackageNameCreate, len(pkgs))
		pkgVersionCreates := make([]*ent.PackageVersionCreate, len(pkgs))

		for i, pkg := range pkgs {
			pkgInput := pkg
			pkgIDs := helpers.GetKey[*model.PkgInputSpec, helpers.PkgIds](pkgInput.PackageInput, helpers.PkgServerKey)
			pkgNameID := generateUUIDKey([]byte(pkgIDs.NameId))
			pkgVersionID := generateUUIDKey([]byte(pkgIDs.VersionId))

			pkgNameCreates[i] = generatePackageNameCreate(tx, &pkgNameID, pkgInput)
			pkgVersionCreates[i] = generatePackageVersionCreate(tx, &pkgVersionID, &pkgNameID, pkgInput)

			pkgNameIDs = append(pkgNameIDs, pkgNameID.String())
			pkgTypes[pkgNameID.String()] = pkgInput.PackageInput.Type
			pkgNamespaces[pkgNameID.String()] = strings.Join([]string{pkgInput.PackageInput.Type, stringOrEmpty(pkgInput.PackageInput.Namespace)}, guacIDSplit)
			pkgVersionIDs = append(pkgVersionIDs, pkgVersionID.String())
		}

		if err := tx.PackageName.CreateBulk(pkgNameCreates...).
			OnConflict(
				sql.ConflictColumns(packagename.FieldName, packagename.FieldNamespace, packagename.FieldType),
			).
			DoNothing().
			Exec(ctx); err != nil {

			return nil, errors.Wrap(err, "bulk upsert pkgName node")
		}

		if err := tx.PackageVersion.CreateBulk(pkgVersionCreates...).
			OnConflict(
				sql.ConflictColumns(
					packageversion.FieldHash,
					packageversion.FieldNameID,
				),
			).
			DoNothing().
			Exec(ctx); err != nil {

			return nil, errors.Wrap(err, "bulk upsert pkgVersion node")
		}
	}
	var collectedPkgIDs []model.PackageIDs
	for i := range pkgVersionIDs {
		collectedPkgIDs = append(collectedPkgIDs, model.PackageIDs{
			PackageTypeID:      toGlobalID(pkgTypeString, pkgTypes[pkgNameIDs[i]]),
			PackageNamespaceID: toGlobalID(pkgNamespaceString, pkgNamespaces[pkgNameIDs[i]]),
			PackageNameID:      toGlobalID(ent.TypePackageName, pkgNameIDs[i]),
			PackageVersionID:   toGlobalID(ent.TypePackageVersion, pkgVersionIDs[i])})
	}

	return &collectedPkgIDs, nil
}

// upsertPackage is a helper function to create or update a package node and its associated edges.
// It is used in multiple places, so we extract it to a function.
func upsertPackage(ctx context.Context, tx *ent.Tx, pkg model.IDorPkgInput) (*model.PackageIDs, error) {
	pkgIDs := helpers.GetKey[*model.PkgInputSpec, helpers.PkgIds](pkg.PackageInput, helpers.PkgServerKey)
	pkgNameID := generateUUIDKey([]byte(pkgIDs.NameId))
	pkgVersionID := generateUUIDKey([]byte(pkgIDs.VersionId))

	pkgNameCreate := generatePackageNameCreate(tx, &pkgNameID, &pkg)

	err := pkgNameCreate.
		OnConflict(sql.ConflictColumns(packagename.FieldName, packagename.FieldNamespace, packagename.FieldType)).
		DoNothing().
		Exec(ctx)
	if err != nil {
		if err != stdsql.ErrNoRows {
			return nil, errors.Wrap(err, "upsert package name")
		}
	}

	pkgVersionCreate := generatePackageVersionCreate(tx, &pkgVersionID, &pkgNameID, &pkg)

	if err := pkgVersionCreate.
		OnConflict(
			sql.ConflictColumns(
				packageversion.FieldHash,
				packageversion.FieldNameID,
			),
		).
		DoNothing().
		Exec(ctx); err != nil {
		if err != stdsql.ErrNoRows {
			return nil, errors.Wrap(err, "upsert package version")
		}
	}

	return &model.PackageIDs{
		PackageTypeID:      toGlobalID(pkgTypeString, pkg.PackageInput.Type),
		PackageNamespaceID: toGlobalID(pkgNamespaceString, strings.Join([]string{pkg.PackageInput.Type, stringOrEmpty(pkg.PackageInput.Namespace)}, guacIDSplit)),
		PackageNameID:      toGlobalID(packagename.Table, pkgNameID.String()),
		PackageVersionID:   toGlobalID(packageversion.Table, pkgVersionID.String())}, nil
}

func withPackageVersionTree() func(*ent.PackageVersionQuery) {
	return func(q *ent.PackageVersionQuery) {
		q.WithName(withPackageNameTree())
	}
}

func withPackageNameTree() func(q *ent.PackageNameQuery) {
	// TODO: (ivanvanderbyl) Filter the depth of this query using preloads
	return func(q *ent.PackageNameQuery) {}
}

func versionHashFromInputSpec(pkg model.PkgInputSpec) string {
	return hashPackageVersion(
		valueOrDefault(pkg.Version, ""),
		valueOrDefault(pkg.Subpath, ""),
		normalizeInputQualifiers(pkg.Qualifiers))
}

func hashPackageVersion(version, subpath string, qualifiers []model.PackageQualifier) string {
	hash := sha1.New()
	hash.Write([]byte(version))
	hash.Write([]byte(subpath))
	qualifiersBuffer := bytes.NewBuffer(nil)

	sort.Slice(qualifiers, func(i, j int) bool { return qualifiers[i].Key < qualifiers[j].Key })

	for _, qualifier := range qualifiers {
		qualifiersBuffer.WriteString(qualifier.Key)
		qualifiersBuffer.WriteString(qualifier.Value)
	}

	hash.Write(qualifiersBuffer.Bytes())
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func normalizeInputQualifiers(inputs []*model.PackageQualifierInputSpec) []model.PackageQualifier {
	if len(inputs) == 0 {
		return nil
	}

	qualifiers := []model.PackageQualifier{}
	for _, q := range inputs {
		qualifiers = append(qualifiers, model.PackageQualifier{
			Key:   q.Key,
			Value: q.Value,
		})
	}

	return qualifiers
}

func packageVersionInputQuery(spec model.PkgInputSpec) predicate.PackageVersion {
	return packageVersionQuery(helper.ConvertPkgInputSpecToPkgSpec(&spec))
}

func packageVersionQuery(filter *model.PkgSpec) predicate.PackageVersion {
	if filter == nil {
		return NoOpSelector()
	}

	rv := []predicate.PackageVersion{
		optionalPredicate(filter.ID, IDEQ),
		optionalPredicate(filter.Version, packageversion.VersionEQ),
		optionalPredicate(filter.Subpath, packageversion.SubpathEQ),
		packageversion.QualifiersMatch(filter.Qualifiers, ptrWithDefault(filter.MatchOnlyEmptyQualifiers, false)),
		packageversion.HasNameWith(
			optionalPredicate(filter.Name, packagename.NameEQ),
			optionalPredicate(filter.Namespace, packagename.NamespaceEQ),
			optionalPredicate(filter.Type, packagename.TypeEQ),
		),
	}

	return packageversion.And(rv...)
}

func packageNameInputQuery(spec model.PkgInputSpec) predicate.PackageName {
	rv := []predicate.PackageName{
		packagename.NameEQ(spec.Name),
		packagename.Namespace(stringOrEmpty(spec.Namespace)),
		packagename.Type(spec.Type),
	}

	return packagename.And(rv...)
}

func packageNameQuery(spec *model.PkgSpec) predicate.PackageName {
	if spec == nil {
		return NoOpSelector()
	}
	query := []predicate.PackageName{
		optionalPredicate(spec.ID, IDEQ),
		optionalPredicate(spec.Name, packagename.NameEQ),
		optionalPredicate(spec.Namespace, packagename.NamespaceEQ),
		optionalPredicate(spec.Type, packagename.TypeEQ),
	}

	return packagename.And(query...)
}

func pkgNameQueryFromPkgSpec(filter *model.PkgSpec) *model.PkgSpec {
	if filter == nil {
		return nil
	}

	return &model.PkgSpec{
		Name:      filter.Name,
		Namespace: filter.Namespace,
		Type:      filter.Type,
		ID:        filter.ID,
	}
}

func backReferencePackageName(pn *ent.PackageName) *ent.PackageName {
	pt := &ent.PackageName{
		ID:        pn.ID,
		Type:      pn.Type,
		Namespace: pn.Namespace,
		Name:      pn.Name,
	}
	return pt
}

func backReferencePackageVersion(pv *ent.PackageVersion) *ent.PackageName {
	if pv != nil &&
		pv.Edges.Name != nil {
		pn := pv.Edges.Name

		// Rebuild a fresh package type from the back reference so that
		// we don't mutate the edges of the original package type.
		pt := &ent.PackageName{
			ID:        pn.ID,
			Type:      pn.Type,
			Namespace: pn.Namespace,
			Name:      pn.Name,
			Edges: ent.PackageNameEdges{
				Versions: []*ent.PackageVersion{pv},
			},
		}
		return pt
	}
	return nil
}

// Each "noun" node will need a "get" for any time an ingest happens on a
// "verb" node that points to it. All but Package and Source are simple. For
// Package, some verbs link to Name and some to Version, or some both. For
// Source, we will want a SourceName.
//
// It is tempting to try to make generic helpers function that are used in both
// this usecase and also in querying, but I find that gets too complicated to
// understand easily.
//
// These queries need to be fast, all the fields are present in an "InputSpec"
// and should allow using the db index.

func getPkgName(ctx context.Context, client *ent.Client, pkgin model.PkgInputSpec) (*ent.PackageName, error) {
	return client.PackageName.Query().Where(packageNameInputQuery(pkgin)).Only(ctx)
}

func getPkgVersion(ctx context.Context, client *ent.Client, pkgin model.PkgInputSpec) (*ent.PackageVersion, error) {
	return client.PackageVersion.Query().Where(packageVersionInputQuery(pkgin)).Only(ctx)
}

func (b *EntBackend) packageTypeNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]model.Node, error) {
	var out []model.Node
	if allowedEdges[model.EdgePackageTypePackageNamespace] {
		query := b.client.PackageName.Query().
			Where([]predicate.PackageName{
				optionalPredicate(&nodeID, packagename.TypeEQ),
			}...).
			Limit(MaxPageSize)

		pkgNames, err := query.All(ctx)
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get pkgType for node ID: %s with error: %w", nodeID, err)
		}

		for _, foundPkgName := range pkgNames {
			out = append(out, &model.Package{
				ID:   toGlobalID(pkgTypeString, foundPkgName.Type),
				Type: foundPkgName.Type,
				Namespaces: []*model.PackageNamespace{
					{
						ID:        toGlobalID(pkgNamespaceString, strings.Join([]string{foundPkgName.Type, foundPkgName.Namespace}, guacIDSplit)),
						Namespace: foundPkgName.Namespace,
						Names:     []*model.PackageName{},
					},
				},
			})
		}
	}
	return out, nil
}

func (b *EntBackend) packageNamespaceNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]model.Node, error) {
	var out []model.Node

	// split to find the type and namespace value
	splitQueryValue := strings.Split(nodeID, guacIDSplit)
	if len(splitQueryValue) != 2 {
		return out, fmt.Errorf("invalid query for packageNamespaceNeighbors with ID %s", nodeID)
	}
	query := b.client.PackageName.Query().
		Where([]predicate.PackageName{
			optionalPredicate(&splitQueryValue[0], packagename.TypeEQ),
			optionalPredicate(&splitQueryValue[1], packagename.NamespaceEQ),
		}...).
		Limit(MaxPageSize)

	pkgNames, err := query.All(ctx)
	if err != nil {
		return []model.Node{}, fmt.Errorf("failed to get packageNamespace for node ID: %s with error: %w", nodeID, err)
	}

	for _, foundPkgName := range pkgNames {
		if allowedEdges[model.EdgePackageNamespacePackageName] {
			out = append(out, &model.Package{
				ID:   toGlobalID(pkgTypeString, foundPkgName.Type),
				Type: foundPkgName.Type,
				Namespaces: []*model.PackageNamespace{
					{
						ID:        toGlobalID(pkgNamespaceString, strings.Join([]string{foundPkgName.Type, foundPkgName.Namespace}, ":")),
						Namespace: foundPkgName.Namespace,
						Names: []*model.PackageName{{
							ID:       toGlobalID(packagename.Table, foundPkgName.ID.String()),
							Name:     foundPkgName.Name,
							Versions: []*model.PackageVersion{},
						}},
					},
				},
			})
		}
		if allowedEdges[model.EdgePackageNamespacePackageType] {
			out = append(out, &model.Package{
				ID:         toGlobalID(pkgTypeString, foundPkgName.Type),
				Type:       foundPkgName.Type,
				Namespaces: []*model.PackageNamespace{},
			})
		}
	}

	return out, nil
}

func (b *EntBackend) packageNameNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]model.Node, error) {
	var out []model.Node

	query := b.client.PackageName.Query().
		Where([]predicate.PackageName{
			optionalPredicate(&nodeID, IDEQ),
		}...)

	if allowedEdges[model.EdgePackageNamePackageVersion] {
		query.
			WithVersions(func(q *ent.PackageVersionQuery) {
				q.WithName()
			})
	}
	if allowedEdges[model.EdgePackageNamePackageNamespace] {
		query.
			Limit(MaxPageSize)
	}
	if allowedEdges[model.EdgePackageHasSourceAt] {
		query.
			WithHasSourceAt(func(q *ent.HasSourceAtQuery) {
				getHasSourceAtObject(q)
			})
	}
	if allowedEdges[model.EdgePackageIsDependency] {
		query.
			WithDependency(func(q *ent.DependencyQuery) {
				getIsDepObject(q)
			})
	}
	if allowedEdges[model.EdgePackageCertifyBad] {
		query.
			WithCertification(func(q *ent.CertificationQuery) {
				q.Where(certification.TypeEQ(certification.TypeBAD))
				getCertificationObject(q)
			})
	}
	if allowedEdges[model.EdgePackageCertifyGood] {
		query.
			WithCertification(func(q *ent.CertificationQuery) {
				q.Where(certification.TypeEQ(certification.TypeGOOD))
				getCertificationObject(q)
			})
	}
	if allowedEdges[model.EdgePackageHasMetadata] {
		query.
			WithMetadata(func(q *ent.HasMetadataQuery) {
				getHasMetadataObject(q)
			})
	}
	if allowedEdges[model.EdgePackagePointOfContact] {
		query.
			WithPoc(func(q *ent.PointOfContactQuery) {
				getPointOfContactObject(q)
			})
	}

	query.
		Limit(MaxPageSize)

	pkgNames, err := query.All(ctx)
	if err != nil {
		return []model.Node{}, fmt.Errorf("failed to query for pkgName with node ID: %s with error: %w", nodeID, err)
	}

	if allowedEdges[model.EdgePackageNamePackageVersion] {
		// sort out the pkgNames so that they each contain one pkg Version edge to output in proper format
		var sortedPkgNames []*ent.PackageName
		for _, collectedPkgName := range pkgNames {
			for _, collectedPkgVersion := range collectedPkgName.Edges.Versions {
				sortedPkgNames = append(sortedPkgNames, backReferencePackageVersion(collectedPkgVersion))
			}
		}
		for _, sortedPkgName := range sortedPkgNames {
			out = append(out, toModelPackage(sortedPkgName))
		}
	}

	for _, foundPkgName := range pkgNames {
		if allowedEdges[model.EdgePackageNamePackageNamespace] {
			out = append(out, &model.Package{
				ID:   toGlobalID(pkgTypeString, foundPkgName.Type),
				Type: foundPkgName.Type,
				Namespaces: []*model.PackageNamespace{
					{
						ID:        toGlobalID(pkgNamespaceString, strings.Join([]string{foundPkgName.Type, foundPkgName.Namespace}, guacIDSplit)),
						Namespace: foundPkgName.Namespace,
						Names:     []*model.PackageName{},
					},
				},
			})
		}
		for _, hasAt := range foundPkgName.Edges.HasSourceAt {
			out = append(out, toModelHasSourceAt(hasAt))
		}
		for _, dep := range foundPkgName.Edges.Dependency {
			out = append(out, toModelIsDependencyWithBackrefs(dep))
		}
		for _, cert := range foundPkgName.Edges.Certification {
			if cert.Type == certification.TypeBAD {
				out = append(out, toModelCertifyBad(cert))
			}
			if cert.Type == certification.TypeGOOD {
				out = append(out, toModelCertifyGood(cert))
			}
		}
		for _, meta := range foundPkgName.Edges.Metadata {
			out = append(out, toModelHasMetadata(meta))
		}
		for _, foundPOC := range foundPkgName.Edges.Poc {
			out = append(out, toModelPointOfContact(foundPOC))
		}
	}

	return out, nil
}

func (b *EntBackend) packageVersionNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]model.Node, error) {
	var out []model.Node
	query := b.client.PackageVersion.Query().
		Where(packageQueryPredicates(&model.PkgSpec{ID: &nodeID}))

	if allowedEdges[model.EdgePackageVersionPackageName] {
		query.
			WithName(func(q *ent.PackageNameQuery) {})
	}
	if allowedEdges[model.EdgePackageHasSourceAt] {
		query.
			WithHasSourceAt(func(q *ent.HasSourceAtQuery) {
				getHasSourceAtObject(q)
			})
	}
	if allowedEdges[model.EdgePackageIsDependency] {
		query.
			WithDependency(func(q *ent.DependencyQuery) {
				getIsDepObject(q)
			}).
			WithDependencySubject(func(q *ent.DependencyQuery) {
				getIsDepObject(q)
			})
	}
	if allowedEdges[model.EdgePackageIsOccurrence] {
		query.
			WithOccurrences(func(q *ent.OccurrenceQuery) {
				getOccurrenceObject(q)
			})
	}
	if allowedEdges[model.EdgePackageCertifyVuln] {
		query.
			WithVuln(func(q *ent.CertifyVulnQuery) {
				getCertVulnObject(q)
			})
	}
	if allowedEdges[model.EdgePackageHasSbom] {
		query.
			WithSbom(func(q *ent.BillOfMaterialsQuery) {
				getSBOMObject(q)
			})
	}
	if allowedEdges[model.EdgePackageCertifyVexStatement] {
		query.
			WithVex(func(q *ent.CertifyVexQuery) {
				getVEXObject(q)
			})
	}
	if allowedEdges[model.EdgePackageCertifyBad] {
		query.
			WithCertification(func(q *ent.CertificationQuery) {
				q.Where(certification.TypeEQ(certification.TypeBAD))
				getCertificationObject(q)
			})
	}
	if allowedEdges[model.EdgePackageCertifyGood] {
		query.
			WithCertification(func(q *ent.CertificationQuery) {
				q.Where(certification.TypeEQ(certification.TypeGOOD))
				getCertificationObject(q)
			})
	}
	if allowedEdges[model.EdgePackagePkgEqual] {
		query.
			WithPkgEqualPkgA(func(q *ent.PkgEqualQuery) {
				getPkgEqualObject(q)
			}).
			WithPkgEqualPkgB(func(q *ent.PkgEqualQuery) {
				getPkgEqualObject(q)
			})
	}
	if allowedEdges[model.EdgePackageHasMetadata] {
		query.
			WithMetadata(func(q *ent.HasMetadataQuery) {
				getHasMetadataObject(q)
			})
	}
	if allowedEdges[model.EdgePackagePointOfContact] {
		query.
			WithPoc(func(q *ent.PointOfContactQuery) {
				getPointOfContactObject(q)
			})
	}
	if allowedEdges[model.EdgePackageCertifyLegal] {
		query.
			WithCertifyLegal(func(q *ent.CertifyLegalQuery) {
				getCertifyLegalObject(q)
			})
	}

	query.
		Limit(MaxPageSize)

	pkgVersions, err := query.All(ctx)
	if err != nil {
		return []model.Node{}, fmt.Errorf("failed to query for packageVersion with node ID: %s with error: %w", nodeID, err)
	}

	var pkgNames []*ent.PackageName
	for _, foundPkgVersion := range pkgVersions {
		if allowedEdges[model.EdgePackageVersionPackageName] {
			pkgNames = append(pkgNames, backReferencePackageVersion(foundPkgVersion))
			for _, foundPkgName := range pkgNames {
				out = append(out, &model.Package{
					ID:   toGlobalID(pkgTypeString, foundPkgName.Type),
					Type: foundPkgName.Type,
					Namespaces: []*model.PackageNamespace{
						{
							ID:        toGlobalID(pkgNamespaceString, strings.Join([]string{foundPkgName.Type, foundPkgName.Namespace}, guacIDSplit)),
							Namespace: foundPkgName.Namespace,
							Names: []*model.PackageName{{
								ID:       toGlobalID(packagename.Table, foundPkgName.ID.String()),
								Name:     foundPkgName.Name,
								Versions: []*model.PackageVersion{},
							}},
						},
					},
				})
			}
		}
		for _, foundHasAt := range foundPkgVersion.Edges.HasSourceAt {
			out = append(out, toModelHasSourceAt(foundHasAt))
		}
		for _, dep := range foundPkgVersion.Edges.Dependency {
			out = append(out, toModelIsDependencyWithBackrefs(dep))
		}
		for _, depSub := range foundPkgVersion.Edges.DependencySubject {
			out = append(out, toModelIsDependencyWithBackrefs(depSub))
		}
		for _, foundOccur := range foundPkgVersion.Edges.Occurrences {
			out = append(out, toModelIsOccurrenceWithSubject(foundOccur))
		}
		for _, foundVuln := range foundPkgVersion.Edges.Vuln {
			out = append(out, toModelCertifyVulnerability(foundVuln))
		}
		for _, foundSBOM := range foundPkgVersion.Edges.Sbom {
			out = append(out, toModelHasSBOM(foundSBOM))
		}
		for _, foundVex := range foundPkgVersion.Edges.Vex {
			out = append(out, toModelCertifyVEXStatement(foundVex))
		}
		for _, foundCert := range foundPkgVersion.Edges.Certification {
			if foundCert.Type == certification.TypeBAD {
				out = append(out, toModelCertifyBad(foundCert))
			}
			if foundCert.Type == certification.TypeGOOD {
				out = append(out, toModelCertifyGood(foundCert))
			}
		}
		for _, pkgEqualA := range foundPkgVersion.Edges.PkgEqualPkgA {
			out = append(out, toModelPkgEqual(pkgEqualA))
		}
		for _, pkgEqualB := range foundPkgVersion.Edges.PkgEqualPkgB {
			out = append(out, toModelPkgEqual(pkgEqualB))
		}
		for _, foundMeta := range foundPkgVersion.Edges.Metadata {
			out = append(out, toModelHasMetadata(foundMeta))
		}
		for _, foundPOC := range foundPkgVersion.Edges.Poc {
			out = append(out, toModelPointOfContact(foundPOC))
		}
		for _, foundLegal := range foundPkgVersion.Edges.CertifyLegal {
			out = append(out, toModelCertifyLegal(foundLegal))
		}
	}

	return out, nil
}
