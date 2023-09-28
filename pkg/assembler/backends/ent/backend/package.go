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

	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagenamespace"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagetype"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
)

func (b *EntBackend) Packages(ctx context.Context, pkgSpec *model.PkgSpec) ([]*model.Package, error) {
	if pkgSpec == nil {
		pkgSpec = &model.PkgSpec{}
	}

	// query := b.client.PackageVersion.Query().Limit(MaxPageSize)

	// query.Where(packageVersionQuery(pkgSpec))
	// query.WithName(withPackageNameTree())
	query := b.client.PackageType.Query().Limit(MaxPageSize)

	paths, isGQL := getPreloads(ctx)

	query.Where(
		optionalPredicate(pkgSpec.Type, packagetype.TypeEQ),
		packagetype.HasNamespacesWith(
			optionalPredicate(pkgSpec.Namespace, packagenamespace.NamespaceEQ),
			packagenamespace.HasNamesWith(
				optionalPredicate(pkgSpec.Name, packagename.NameEQ),
				packagename.HasVersionsWith(
					optionalPredicate(pkgSpec.ID, IDEQ),
					optionalPredicate(pkgSpec.Version, packageversion.VersionEqualFold),
					optionalPredicate(pkgSpec.Subpath, packageversion.SubpathEqualFold),
					packageversion.QualifiersMatch(pkgSpec.Qualifiers, ptrWithDefault(pkgSpec.MatchOnlyEmptyQualifiers, false)),
				),
			),
		),
	)

	if PathContains(paths, "namespaces") || !isGQL {
		query.WithNamespaces(func(q *ent.PackageNamespaceQuery) {
			q.Where(optionalPredicate(pkgSpec.Namespace, packagenamespace.NamespaceEQ))

			if PathContains(paths, "namespaces.names") || !isGQL {
				q.WithNames(func(q *ent.PackageNameQuery) {
					q.Where(optionalPredicate(pkgSpec.Name, packagename.NameEQ))

					if PathContains(paths, "namespaces.names.versions") || !isGQL {
						q.WithVersions(func(q *ent.PackageVersionQuery) {
							q.Where(
								optionalPredicate(pkgSpec.ID, IDEQ),
								optionalPredicate(pkgSpec.Version, packageversion.VersionEQ),
								optionalPredicate(pkgSpec.Subpath, packageversion.SubpathEqualFold),
								packageversion.QualifiersMatch(pkgSpec.Qualifiers, ptrWithDefault(pkgSpec.MatchOnlyEmptyQualifiers, false)),
							)
						})
					}
				})
			}
		})
	}

	pkgs, err := query.All(ctx)
	if err != nil {
		return nil, err
	}

	// return collect(pkgs, func(v *ent.PackageVersion) *model.Package {
	// 	return toModelPackage(backReferencePackageVersion(v))
	// }), nil

	return collect(pkgs, toModelPackage), nil
}

func (b *EntBackend) IngestPackages(ctx context.Context, pkgs []*model.PkgInputSpec) ([]*model.Package, error) {
	// FIXME: (ivanvanderbyl) This will be suboptimal because we can't batch insert relations with upserts. See Readme.
	models := make([]*model.Package, len(pkgs))
	for i, pkg := range pkgs {
		p, err := b.IngestPackage(ctx, *pkg)
		if err != nil {
			return nil, err
		}
		models[i] = p
	}
	return models, nil
}

func (b *EntBackend) IngestPackage(ctx context.Context, pkg model.PkgInputSpec) (*model.Package, error) {
	pkgVersion, err := WithinTX(ctx, b.client, func(ctx context.Context) (*ent.PackageVersion, error) {
		p, err := upsertPackage(ctx, ent.TxFromContext(ctx), pkg)
		if err != nil {
			return nil, errors.Wrap(err, "failed to upsert package")
		}
		return p, nil
	})
	if err != nil {
		return nil, err
	}

	return toModelPackage(backReferencePackageVersion(pkgVersion.Unwrap())), nil
}

// upsertPackage is a helper function to create or update a package node and its associated edges.
// It is used in multiple places, so we extract it to a function.
func upsertPackage(ctx context.Context, client *ent.Tx, pkg model.PkgInputSpec) (*ent.PackageVersion, error) {

	pkgID, err := client.PackageType.Create().
		SetType(pkg.Type).
		OnConflict(sql.ConflictColumns(packagetype.FieldType)).
		DoNothing().
		ID(ctx)
	if err != nil {
		if err != stdsql.ErrNoRows {
			return nil, errors.Wrap(err, "upsert package node")
		}
		pkgID, err = client.PackageType.Query().
			Where(packagetype.TypeEQ(pkg.Type)).
			OnlyID(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "get package type")
		}
	}

	nsID, err := client.PackageNamespace.Create().
		SetPackageID(pkgID).
		SetNamespace(valueOrDefault(pkg.Namespace, "")).
		OnConflict(sql.ConflictColumns(packagenamespace.FieldNamespace, packagenamespace.FieldPackageID)).
		DoNothing().
		ID(ctx)
	if err != nil {
		if err != stdsql.ErrNoRows {
			return nil, errors.Wrap(err, "upsert package namespace")
		}
		nsID, err = client.PackageNamespace.Query().
			Where(
				packagenamespace.PackageIDEQ(pkgID),
				packagenamespace.NamespaceEQ(valueOrDefault(pkg.Namespace, "")),
			).
			OnlyID(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "get package namespace")
		}
	}

	nameID, err := client.PackageName.Create().
		SetNamespaceID(nsID).
		SetName(pkg.Name).
		OnConflict(sql.ConflictColumns(packagename.FieldName, packagename.FieldNamespaceID)).
		DoNothing().
		ID(ctx)
	if err != nil {
		if err != stdsql.ErrNoRows {
			return nil, errors.Wrap(err, "upsert package name")
		}
		nameID, err = client.PackageName.Query().
			Where(
				packagename.NamespaceIDEQ(nsID),
				packagename.NameEQ(pkg.Name),
			).
			OnlyID(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "get package name")
		}
	}

	id, err := client.PackageVersion.Create().
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
		id, err = client.PackageVersion.Query().
			Where(
				packageversion.HashEQ(versionHashFromInputSpec(pkg)),
				packageversion.NameIDEQ(nameID),
			).
			OnlyID(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "get package version")
		}
	}

	pv, err := client.PackageVersion.Query().Where(packageversion.ID(id)).
		WithName(withPackageNameTree()).
		Only(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "get package version")
	}

	return pv, nil
}

func withPackageVersionTree() func(*ent.PackageVersionQuery) {
	return func(q *ent.PackageVersionQuery) {
		q.WithName(withPackageNameTree())
	}
}

func withPackageNameTree() func(q *ent.PackageNameQuery) {
	// TODO: (ivanvanderbyl) Filter the depth of this query using preloads
	return func(q *ent.PackageNameQuery) {
		q.WithNamespace(func(q *ent.PackageNamespaceQuery) {
			q.WithPackage()
		})
	}
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
			packagename.HasNamespaceWith(
				optionalPredicate(filter.Namespace, packagenamespace.Namespace),
				packagenamespace.HasPackageWith(
					optionalPredicate(filter.Type, packagetype.Type),
				),
			),
		),
	}

	return packageversion.And(rv...)
}

func packageNameInputQuery(spec model.PkgInputSpec) predicate.PackageName {
	rv := []predicate.PackageName{
		packagename.NameEQ(spec.Name),
		packagename.HasNamespaceWith(
			packagenamespace.Namespace(stringOrEmpty(spec.Namespace)),
			packagenamespace.HasPackageWith(
				packagetype.TypeEQ(spec.Type),
			),
		),
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
		packagename.HasNamespaceWith(
			optionalPredicate(spec.Namespace, packagenamespace.Namespace),
			packagenamespace.HasPackageWith(
				optionalPredicate(spec.Type, packagetype.Type),
			),
		),
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

func backReferencePackageVersion(pv *ent.PackageVersion) *ent.PackageType {
	if pv != nil &&
		pv.Edges.Name != nil &&
		pv.Edges.Name.Edges.Namespace != nil &&
		pv.Edges.Name.Edges.Namespace.Edges.Package != nil {
		pn := pv.Edges.Name
		ns := pn.Edges.Namespace

		// Rebuild a fresh package type from the back reference so that
		// we don't mutate the edges of the original package type.
		pt := &ent.PackageType{
			ID:   ns.Edges.Package.ID,
			Type: ns.Edges.Package.Type,
			Edges: ent.PackageTypeEdges{
				Namespaces: []*ent.PackageNamespace{
					{
						ID:        ns.ID,
						PackageID: ns.PackageID,
						Namespace: ns.Namespace,
						Edges: ent.PackageNamespaceEdges{
							Names: []*ent.PackageName{
								{
									ID:          pn.ID,
									NamespaceID: pn.NamespaceID,
									Name:        pn.Name,
									Edges: ent.PackageNameEdges{
										Versions: []*ent.PackageVersion{pv},
									},
								},
							},
						},
					},
				},
			},
		}
		return pt
	}
	return nil
}

func backReferencePackageName(pn *ent.PackageName) *ent.PackageType {
	if pn.Edges.Namespace != nil &&
		pn.Edges.Namespace.Edges.Package != nil {
		ns := pn.Edges.Namespace
		pt := ns.Edges.Package
		ns.Edges.Names = []*ent.PackageName{pn}
		pt.Edges.Namespaces = []*ent.PackageNamespace{ns}
		return pt
	}
	return nil
}

func backReferencePackageNamespace(pns *ent.PackageNamespace) *ent.PackageType {
	if pns.Edges.Package != nil {
		pt := pns.Edges.Package
		pt.Edges.Namespaces = []*ent.PackageNamespace{pns}
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
