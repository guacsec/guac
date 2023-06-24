package backend

import (
	"bytes"
	"context"
	"crypto/sha1"
	"fmt"
	"sort"

	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagenamespace"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagenode"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
)

func (b *EntBackend) Packages(ctx context.Context, pkgSpec *model.PkgSpec) ([]*model.Package, error) {
	query := b.client.PackageNode.Query().Order(ent.Asc(packagenode.FieldType))

	paths := getPreloads(ctx)

	if pkgSpec == nil {
		pkgSpec = &model.PkgSpec{}
	}

	query.Where(optionalPredicate(pkgSpec.Type, packagenode.TypeEQ))

	if PathContains(paths, "namespaces") {
		query.WithNamespaces(func(q *ent.PackageNamespaceQuery) {
			q.Order(ent.Asc(packagenamespace.FieldNamespace))
			q.Where(optionalPredicate(pkgSpec.Namespace, packagenamespace.NamespaceEQ))

			if PathContains(paths, "namespaces.names") {
				q.WithNames(func(q *ent.PackageNameQuery) {
					q.Order(ent.Asc(packagename.FieldName))
					q.Where(optionalPredicate(pkgSpec.Name, packagename.NameEQ))

					if PathContains(paths, "namespaces.names.versions") {
						q.WithVersions(func(q *ent.PackageVersionQuery) {
							q.Order(ent.Asc(packageversion.FieldVersion))
							q.Where(
								optionalPredicate(pkgSpec.Version, packageversion.VersionEQ),
								optionalPredicate(pkgSpec.Subpath, packageversion.SubpathEQ),
								packageversion.QualifiersMatchSpec(pkgSpec.Qualifiers),
							)
						})
					}
				})
			}
		})
	}

	// FIXME: (ivanvanderbyl) This could be much more compact and use a single query as above.
	if pkgSpec != nil {
		query.Where(optionalPredicate(pkgSpec.ID, IDEQ))
	} else {
		query.Limit(100)
	}

	pkgs, err := query.All(ctx)
	if err != nil {
		return nil, err
	}

	return collect(pkgs, toModelPackage), nil
}

func (b *EntBackend) IngestPackage(ctx context.Context, pkg model.PkgInputSpec) (*model.Package, error) {
	pvID, err := WithinTX(ctx, b.client, func(ctx context.Context) (*int, error) {
		client := ent.FromContext(ctx)
		pvID, err := upsertPackage(ctx, client, pkg)
		if err != nil {
			return nil, err
		}

		return &pvID, nil
	})
	if err != nil {
		return nil, err
	}

	record, err := b.client.PackageVersion.Query().
		Where(packageversion.ID(*pvID)).QueryName().QueryNamespace().QueryPackage().
		WithNamespaces(func(q *ent.PackageNamespaceQuery) {
			q.Order(ent.Asc(packagenamespace.FieldNamespace))
			q.Where(packagenamespace.Namespace(valueOrDefault(pkg.Namespace, "")))
			q.WithNames(func(q *ent.PackageNameQuery) {
				q.Order(ent.Asc(packagename.FieldName))
				q.Where(packagename.Name(pkg.Name))
				q.WithVersions(func(q *ent.PackageVersionQuery) {
					q.Order(ent.Asc(packageversion.FieldVersion))
					q.Where(packageversion.Hash(versionHashFromInputSpec(pkg)))
				})
			})
		}).
		Only(ctx)

	// TODO: Figure out if we need to preload the edges from the graphql query
	// record, err := b.client.PackageNode.Query().Where(packagenode.ID(*pvID)).
	// 	WithNamespaces(func(q *PackageNamespaceQuery) {
	// 		q.Order(Asc(packagenamespace.FieldNamespace))
	// 		q.WithNames(func(q *PackageNameQuery) {
	// 			q.Order(Asc(packagename.FieldName))
	// 			q.WithVersions(func(q *PackageVersionQuery) {
	// 				q.Order(Asc(packageversion.FieldVersion))
	// 			})
	// 		})
	// 	}).
	// 	Only(ctx)
	if err != nil {
		return nil, err
	}

	return toModelPackage(record), nil
}

// upsertPackage is a helper function to create or update a package node and its associated edges.
// It is used in multiple places, so we extract it to a function.
func upsertPackage(ctx context.Context, client *ent.Client, pkg model.PkgInputSpec) (int, error) {
	pkgID, err := client.PackageNode.Create().SetType(pkg.Type).
		OnConflict(sql.ConflictColumns(packagenode.FieldType)).UpdateNewValues().ID(ctx)
	if err != nil {
		return 0, errors.Wrap(err, "upsert package node")
	}

	if pkg.Namespace == nil {
		empty := ""
		pkg.Namespace = &empty
	}

	nsID, err := client.PackageNamespace.Create().SetPackageID(pkgID).SetNamespace(valueOrDefault(pkg.Namespace, "")).
		OnConflict(sql.ConflictColumns(packagenamespace.FieldNamespace, packagenamespace.FieldPackageID)).UpdateNewValues().ID(ctx)
	if err != nil {
		return 0, errors.Wrap(err, "upsert package namespace")
	}

	nameID, err := client.PackageName.Create().SetNamespaceID(nsID).SetName(pkg.Name).
		OnConflict(sql.ConflictColumns(packagename.FieldName, packagename.FieldNamespaceID)).UpdateNewValues().ID(ctx)
	if err != nil {
		return 0, errors.Wrap(err, "upsert package name")
	}

	if pkg.Version == nil {
		empty := ""
		pkg.Version = &empty
	}

	pvID, err := client.PackageVersion.Create().
		SetNameID(nameID).
		SetVersion(valueOrDefault(pkg.Version, "")).
		SetSubpath(valueOrDefault(pkg.Subpath, "")).
		SetQualifiers(normalizeInputQualifiers(pkg.Qualifiers)).
		SetHash(versionHashFromInputSpec(pkg)).
		OnConflict(
			sql.ConflictColumns(
				packageversion.FieldHash,
				packageversion.FieldNameID,
			),
		).
		UpdateNewValues().
		ID(ctx)
	if err != nil {
		return 0, errors.Wrap(err, "upsert package version")
	}
	return pvID, nil
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
	qualifiers := []model.PackageQualifier{}
	for _, q := range inputs {
		qualifiers = append(qualifiers, model.PackageQualifier{
			Key:   q.Key,
			Value: q.Value,
		})
	}

	return qualifiers
}

func pkgVersionPredicates(spec *model.PkgSpec) []predicate.PackageVersion {
	if spec == nil {
		return nil
	}
	rv := []predicate.PackageVersion{
		optionalPredicate(spec.ID, IDEQ),
		optionalPredicate(spec.Version, packageversion.Version),
		optionalPredicate(spec.Subpath, packageversion.Subpath),
		packageversion.QualifiersMatchSpec(spec.Qualifiers),
		packageversion.HasNameWith(
			optionalPredicate(spec.Name, packagename.Name),
			packagename.HasNamespaceWith(
				optionalPredicate(spec.Namespace, packagenamespace.Namespace),
				packagenamespace.HasPackageWith(
					optionalPredicate(spec.Type, packagenode.Type),
				),
			),
		),
	}

	return rv
}

func pkgNamePredicates(spec *model.PkgNameSpec) []predicate.PackageName {
	if spec == nil {
		return nil
	}
	return []predicate.PackageName{
		optionalPredicate(spec.ID, IDEQ),
		optionalPredicate(spec.Name, packagename.Name),
		packagename.HasNamespaceWith(
			optionalPredicate(spec.Namespace, packagenamespace.Namespace),
			packagenamespace.HasPackageWith(
				optionalPredicate(spec.Type, packagenode.Type),
			),
		),
	}
}
