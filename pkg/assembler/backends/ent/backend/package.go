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
	"crypto/sha256"
	stdsql "database/sql"
	"fmt"
	"sort"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
)

const (
	pkgTypeString      = "pkgType"
	pkgNamespaceString = "pkgNamespace"
)

func (b *EntBackend) Packages(ctx context.Context, pkgSpec *model.PkgSpec) ([]*model.Package, error) {
	if pkgSpec == nil {
		pkgSpec = &model.PkgSpec{}
	}

	query := b.client.PackageName.Query().Limit(MaxPageSize)

	// TODO: Fix preloads
	//paths, isGQL := getPreloads(ctx)

	query.Where(
		optionalPredicate(pkgSpec.Type, packagename.TypeEQ),
		optionalPredicate(pkgSpec.Namespace, packagename.NamespaceEQ),
		optionalPredicate(pkgSpec.Name, packagename.NameEQ),
		packagename.HasVersionsWith(
			optionalPredicate(pkgSpec.ID, IDEQ),
			optionalPredicate(pkgSpec.Version, packageversion.VersionEqualFold),
			optionalPredicate(pkgSpec.Subpath, packageversion.SubpathEqualFold),
			packageversion.QualifiersMatch(pkgSpec.Qualifiers, ptrWithDefault(pkgSpec.MatchOnlyEmptyQualifiers, false)),
		),
	)

	// TODO: Fix preloads
	// if slices.Contains(paths, "namespaces") || !isGQL {
	// 	query.WithNamedVersions(func(q *ent.PackageNameQuery) {
	// 		q.Where(optionalPredicate(pkgSpec.Namespace, packagenamespace.NamespaceEQ))
	// 		if slices.Contains(paths, "namespaces.names") || !isGQL {
	// 			q.WithNames(func(q *ent.PackageNameQuery) {
	// 				q.Where(optionalPredicate(pkgSpec.Name, packagename.NameEQ))
	// 				q.Where(optionalPredicate(pkgSpec.Namespace, packagename.NameEQ))

	// 				if slices.Contains(paths, "namespaces.names.versions") || !isGQL {
	// 					q.WithVersions(func(q *ent.PackageVersionQuery) {
	// 						q.Where(
	// 							optionalPredicate(pkgSpec.ID, IDEQ),
	// 							optionalPredicate(pkgSpec.Version, packageversion.VersionEQ),
	// 							optionalPredicate(pkgSpec.Subpath, packageversion.SubpathEqualFold),
	// 							packageversion.QualifiersMatch(pkgSpec.Qualifiers, ptrWithDefault(pkgSpec.MatchOnlyEmptyQualifiers, false)),
	// 						)
	// 					})
	// 				}
	// 			})
	// 		}
	// 	})
	// }

	pkgs, err := query.All(ctx)
	if err != nil {
		return nil, err
	}

	return collect(pkgs, toModelPackage), nil
}

func (b *EntBackend) IngestPackages(ctx context.Context, pkgs []*model.IDorPkgInput) ([]*model.PackageIDs, error) {
	// FIXME: (ivanvanderbyl) This will be suboptimal because we can't batch insert relations with upserts. See Readme.
	pkgsID := make([]*model.PackageIDs, len(pkgs))
	eg, ctx := errgroup.WithContext(ctx)
	for i := range pkgs {
		index := i
		pkg := pkgs[index]
		concurrently(eg, func() error {
			p, err := b.IngestPackage(ctx, *pkg)
			if err == nil {
				pkgsID[index] = p
			}
			return err
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, err
	}
	return pkgsID, nil
}

func (b *EntBackend) IngestPackage(ctx context.Context, pkg model.IDorPkgInput) (*model.PackageIDs, error) {
	pkgVersionID, err := WithinTX(ctx, b.client, func(ctx context.Context) (*model.PackageIDs, error) {
		p, err := upsertPackage(ctx, ent.TxFromContext(ctx), *pkg.PackageInput)
		if err != nil {
			return nil, errors.Wrap(err, "failed to upsert package")
		}
		return p, nil
	})
	if err != nil {
		return nil, err
	}

	return pkgVersionID, nil
}

// upsertPackage is a helper function to create or update a package node and its associated edges.
// It is used in multiple places, so we extract it to a function.
func upsertPackage(ctx context.Context, client *ent.Tx, pkg model.PkgInputSpec) (*model.PackageIDs, error) {
	pkgIDs := helper.GuacPkgId(pkg)
	pkgNameID := uuid.NewHash(sha256.New(), uuid.NameSpaceDNS, []byte(pkgIDs.NameId), 5)
	pkgVersionID := uuid.NewHash(sha256.New(), uuid.NameSpaceDNS, []byte(pkgIDs.VersionId), 5)

	nameID, err := client.PackageName.Create().
		SetID(pkgNameID).
		SetType(pkg.Type).
		SetNamespace(valueOrDefault(pkg.Namespace, "")).
		SetName(pkg.Name).
		OnConflict(sql.ConflictColumns(packagename.FieldName, packagename.FieldNamespace, packagename.FieldType)).
		DoNothing().
		ID(ctx)
	if err != nil {
		if err != stdsql.ErrNoRows {
			return nil, errors.Wrap(err, "upsert package name")
		}
		nameID = pkgNameID
	}

	id, err := client.PackageVersion.Create().
		SetID(pkgVersionID).
		SetNameID(nameID).
		SetNillableVersion(pkg.Version).
		SetSubpath(ptrWithDefault(pkg.Subpath, "")).
		SetQualifiers(normalizeInputQualifiers(pkg.Qualifiers)).
		SetHash(versionHashFromInputSpec(pkg)).
		OnConflict(
			sql.ConflictColumns(
				packageversion.FieldHash,
				packageversion.FieldNameID,
			),
		).
		DoNothing().
		ID(ctx)
	if err != nil {
		if err != stdsql.ErrNoRows {
			return nil, errors.Wrap(err, "upsert package version")
		}
		id = pkgVersionID
	}

	return &model.PackageIDs{
		PackageTypeID:      fmt.Sprintf("%s:%s", pkgTypeString, pkgNameID.String()),
		PackageNamespaceID: fmt.Sprintf("%s:%s", pkgNamespaceString, pkgNameID.String()),
		PackageNameID:      nameID.String(),
		PackageVersionID:   id.String()}, nil
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

//func qualifiersToSpecQualifiers(q []*model.PackageQualifierInputSpec) []*model.PackageQualifierSpec {
//	results := make([]*model.PackageQualifierSpec, len(q))
//	for i, s := range q {
//		results[i] = &model.PackageQualifierSpec{
//			Key:   s.Key,
//			Value: &s.Value,
//		}
//	}
//	return results
//}

func packageVersionInputQuery(spec model.PkgInputSpec) predicate.PackageVersion {
	return packageVersionQuery(helper.ConvertPkgInputSpecToPkgSpec(&spec))

	// rv := []predicate.PackageVersion{
	// 	packageversion.VersionEQ(stringOrEmpty(spec.Version)),
	// 	packageversion.SubpathEQ(stringOrEmpty(spec.Subpath)),
	// 	packageversion.QualifiersMatchSpec(pkgQualifierInputSpecToQuerySpec(spec.Qualifiers)),
	// 	packageversion.HasNameWith(
	// 		packagename.NameEQ(spec.Name),
	// 		packagename.HasNamespaceWith(
	// 			packagenamespace.Namespace(stringOrEmpty(spec.Namespace)),
	// 			packagenamespace.HasPackageWith(
	// 				packagetype.TypeEQ(spec.Type),
	// 			),
	// 		),
	// 	),
	// }

	// return packageversion.And(rv...)
}

//func isPackageVersionQuery(filter *model.PkgSpec) bool {
//	if filter == nil {
//		return false
//	}
//
//	return filter.Version != nil || filter.Subpath != nil || filter.Qualifiers != nil
//}

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
			optionalPredicate(filter.Name, packagename.Name),
			optionalPredicate(filter.Namespace, packagename.Namespace),
			optionalPredicate(filter.Type, packagename.Type),
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
		optionalPredicate(spec.Name, packagename.Name),
		optionalPredicate(spec.Namespace, packagename.Namespace),
		optionalPredicate(spec.Namespace, packagename.Type),
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
	// return client.PackageType.Query().
	// 	Where(packagetype.Type(pkgin.Type)).
	// 	QueryNamespaces().Where(packagenamespace.NamespaceEQ(valueOrDefault(pkgin.Namespace, ""))).
	// 	QueryNames().Where(packagename.NameEQ(pkgin.Name)).
	// 	QueryVersions().
	// 	Where(
	// 		packageVersionInputQuery(pkgin),
	// 	).
	// 	Only(ctx)
}
