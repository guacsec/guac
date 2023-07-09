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
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagetype"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
)

func (b *EntBackend) Packages(ctx context.Context, pkgSpec *model.PkgSpec) ([]*model.Package, error) {
	if pkgSpec == nil {
		pkgSpec = &model.PkgSpec{}
	}

	query := b.client.PackageType.Query().Limit(MaxPageSize)
	paths, isGQL := getPreloads(ctx)

	query.Where(
		optionalPredicate(pkgSpec.Type, packagetype.TypeEQ),
	)

	if PathContains(paths, "namespaces") || !isGQL {
		query.WithNamespaces(func(q *ent.PackageNamespaceQuery) {
			q.Order(ent.Asc(packagenamespace.FieldNamespace))
			q.Where(optionalPredicate(pkgSpec.Namespace, packagenamespace.NamespaceEQ))

			if PathContains(paths, "namespaces.names") || !isGQL {
				q.WithNames(func(q *ent.PackageNameQuery) {
					q.Order(ent.Asc(packagename.FieldName))
					q.Where(optionalPredicate(pkgSpec.Name, packagename.NameEQ))

					if PathContains(paths, "namespaces.names.versions") || !isGQL {
						q.WithVersions(func(q *ent.PackageVersionQuery) {
							q.Order(ent.Asc(packageversion.FieldVersion))
							q.Where(
								optionalPredicate(pkgSpec.ID, IDEQ),
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

	pkgs, err := query.All(ctx)
	if err != nil {
		return nil, err
	}

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
	pkgID, err := client.PackageType.Create().SetType(pkg.Type).
		OnConflict(sql.ConflictColumns(packagetype.FieldType)).UpdateNewValues().ID(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "upsert package node")
	}

	nsID, err := client.PackageNamespace.Create().SetPackageID(pkgID).SetNamespace(valueOrDefault(pkg.Namespace, "")).
		OnConflict(sql.ConflictColumns(packagenamespace.FieldNamespace, packagenamespace.FieldPackageID)).UpdateNewValues().ID(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "upsert package namespace")
	}

	nameID, err := client.PackageName.Create().SetNamespaceID(nsID).SetName(pkg.Name).
		OnConflict(sql.ConflictColumns(packagename.FieldName, packagename.FieldNamespaceID)).UpdateNewValues().ID(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "upsert package name")
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
		return nil, errors.Wrap(err, "upsert package version")
	}

	pv, err := client.PackageVersion.Query().Where(packageversion.IDEQ(pvID)).
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
	qualifiers := []model.PackageQualifier{}
	for _, q := range inputs {
		qualifiers = append(qualifiers, model.PackageQualifier{
			Key:   q.Key,
			Value: q.Value,
		})
	}

	return qualifiers
}

func pkgVersionInputPredicates(spec *model.PkgInputSpec) predicate.PackageVersion {
	if spec == nil {
		return NoOpSelector()
	}

	rv := []predicate.PackageVersion{
		packageversion.VersionEQ(stringOrEmpty(spec.Version)),
		packageversion.SubpathEQ(stringOrEmpty(spec.Subpath)),
		packageversion.QualifiersMatchSpec(pkgQualifierInputSpecToQuerySpec(spec.Qualifiers)),
		packageversion.HasNameWith(
			packagename.NameEQ(spec.Name),
			packagename.HasNamespaceWith(
				packagenamespace.Namespace(stringOrEmpty(spec.Namespace)),
				packagenamespace.HasPackageWith(
					packagetype.TypeEQ(spec.Type),
				),
			),
		),
	}

	return packageversion.And(rv...)
}

func pkgVersionPredicates(spec *model.PkgSpec) predicate.PackageVersion {
	if spec == nil {
		return NoOpSelector()
	}

	rv := []predicate.PackageVersion{
		optionalPredicate(spec.ID, IDEQ),
		optionalPredicate(spec.Version, packageversion.VersionEQ),
		optionalPredicate(spec.Subpath, packageversion.SubpathEQ),
		packageversion.QualifiersMatchSpec(spec.Qualifiers),

		packageversion.HasNameWith(
			optionalPredicate(spec.Name, packagename.Name),
			packagename.HasNamespaceWith(
				optionalPredicate(spec.Namespace, packagenamespace.Namespace),
				packagenamespace.HasPackageWith(
					optionalPredicate(spec.Type, packagetype.Type),
				),
			),
		),
	}

	return packageversion.And(rv...)
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
				optionalPredicate(spec.Type, packagetype.Type),
			),
		),
	}
}
