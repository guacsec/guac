package ent

import (
	"context"

	entsql "entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/isdependency"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/isoccurrence"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagenamespace"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagenode"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

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

func (b *EntBackend) getPkgName(ctx context.Context, pkgin *model.PkgInputSpec) (*PackageName, error) {
	t, err := b.client.PackageNode.Query().
		Where(packagenode.Type(pkgin.Type)).
		Only(ctx)
	if err != nil {
		return nil, err
	}
	ns, err := t.QueryNamespaces().
		Where(packagenamespace.Namespace(valueOrDefault(pkgin.Namespace, ""))).
		Only(ctx)
	if err != nil {
		return nil, err
	}
	return ns.QueryNames().
		Where(packagename.Name(pkgin.Name)). // Does this combine with link up to namespace to use index??
		Only(ctx)
}

func (b *EntBackend) getPkgVersion(ctx context.Context, pkgin *model.PkgInputSpec) (*PackageVersion, error) {
	n, err := b.getPkgName(ctx, pkgin)
	if err != nil {
		return nil, err
	}
	return n.QueryVersions().
		Where(packageversion.Version(valueOrDefault(pkgin.Version, ""))).
		Where(packageversion.Subpath(valueOrDefault(pkgin.Subpath, ""))).
		Where(packageversion.Qualifiers(qualifiersToString(pkgin.Qualifiers))).
		Only(ctx)
}

func (b *EntBackend) getArtifact(ctx context.Context, artin *model.ArtifactInputSpec) (*Artifact, error) {
	return b.client.Artifact.Query().
		Where(artifact.Algorithm(artin.Algorithm)).
		Where(artifact.Digest(artin.Digest)).
		Only(ctx)
}

// When verb nodes point to a PackageName/Version or SourceName we need to
// rebuild the full top level tree object with just the nested objects that are
// part of the path to that node

func pkgTreeFromVersion(ctx context.Context, pv *PackageVersion) (*PackageNode, error) {
	n, err := pv.QueryName().Only(ctx)
	if err != nil {
		return nil, err
	}
	ns, err := n.QueryNamespace().Only(ctx)
	if err != nil {
		return nil, err
	}
	return ns.QueryPackage().
		WithNamespaces(func(q *PackageNamespaceQuery) {
			q.Where(packagenamespace.Namespace(ns.Namespace))
			q.WithNames(func(q *PackageNameQuery) {
				q.Where(packagename.Name(n.Name))
				q.WithVersions(func(q *PackageVersionQuery) {
					q.Where(packageversion.Version(pv.Version))
					q.Where(packageversion.Subpath(pv.Subpath))
					q.Where(packageversion.Qualifiers(pv.Qualifiers))
				})
			})
		}).
		Only(ctx)
}

func pkgTreeFromName(ctx context.Context, pn *PackageName) (*PackageNode, error) {
	ns, err := pn.QueryNamespace().Only(ctx)
	if err != nil {
		return nil, err
	}
	return ns.QueryPackage().
		WithNamespaces(func(q *PackageNamespaceQuery) {
			q.Where(packagenamespace.Namespace(ns.Namespace))
			q.WithNames(func(q *PackageNameQuery) {
				q.Where(packagename.Name(pn.Name))
			})
		}).
		Only(ctx)
}

func (b *EntBackend) IsDependency(ctx context.Context, isDependencySpec *model.IsDependencySpec) ([]*model.IsDependency, error) {
	funcName := "IsDependency"
	query := b.client.IsDependency.Query().Order(Asc(isdependency.FieldID))

	if isDependencySpec != nil {
		query.Where(
			IDEQ(isDependencySpec.ID),
			isdependency.HasPackageWith(pkgVersionPreds(isDependencySpec.Package)...),
			isdependency.HasDependentPackageWith(pkgNamePreds(isDependencySpec.DependentPackage)...),
			optionalPredicate(isDependencySpec.VersionRange, isdependency.VersionRange),
			optionalPredicate(isDependencySpec.Justification, isdependency.Justification),
			optionalPredicate(isDependencySpec.Origin, isdependency.Origin),
			optionalPredicate(isDependencySpec.Collector, isdependency.Collector),
		)
		if isDependencySpec.DependencyType != nil {
			query.Where(isdependency.DependencyType(string(*isDependencySpec.DependencyType)))
		}
	} else {
		query.Limit(100)
	}

	ids, err := query.
		WithPackage().
		WithDependentPackage().
		All(ctx)
	if err != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
	}

	rv, err := collectWithError(ctx, ids, toModelIsDependency)
	if err != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
	}
	return rv, nil
}

func (b *EntBackend) IngestDependency(ctx context.Context, pkg model.PkgInputSpec, depPkg model.PkgInputSpec, dependency model.IsDependencyInputSpec) (*model.IsDependency, error) {
	funcName := "IngestDependency"

	recordID, err := WithinTX(ctx, b.client, func(ctx context.Context) (*int, error) {
		client := FromContext(ctx)
		p, err := b.getPkgVersion(ctx, &pkg)
		if err != nil {
			return nil, err
		}
		dp, err := b.getPkgName(ctx, &depPkg)
		if err != nil {
			return nil, err
		}
		id, err := client.IsDependency.Create().
			SetPackage(p). // Should I be using SetPackageID() here?
			SetDependentPackage(dp).
			SetVersionRange(dependency.VersionRange).
			SetDependencyType(string(dependency.DependencyType)).
			SetJustification(dependency.Justification).
			SetOrigin(dependency.Origin).
			SetCollector(dependency.Collector).
			OnConflict(
				entsql.ConflictColumns(
					isdependency.FieldPackageID,
					isdependency.FieldDependentPackageID,
					isdependency.FieldVersionRange,
					isdependency.FieldDependencyType,
					isdependency.FieldJustification,
					isdependency.FieldOrigin,
					isdependency.FieldCollector,
				),
			).
			UpdateNewValues().ID(ctx)
		if err != nil {
			return nil, err
		}
		return &id, nil
	})
	if err != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
	}

	// Upsert only gets ID, so need to query the object
	record, err := b.client.IsDependency.Query().
		Where(isdependency.ID(*recordID)).
		WithPackage().
		WithDependentPackage().
		Only(ctx)
	if err != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
	}

	return toModelIsDependency(ctx, record)
}

func (b *EntBackend) IngestOccurrence(ctx context.Context, subject model.PackageOrSourceInput, art model.ArtifactInputSpec, occurrence model.IsOccurrenceInputSpec) (*model.IsOccurrence, error) {
	funcName := "IngestOccurrence"
	if err := helper.ValidatePackageOrSourceInput(&subject, "IngestOccurrence"); err != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
	}

	recordID, err := WithinTX(ctx, b.client, func(ctx context.Context) (*int, error) {
		client := FromContext(ctx)
		var p *PackageVersion
		//var s *ent.SourceName
		if subject.Package != nil {
			var err error
			p, err = b.getPkgVersion(ctx, subject.Package)
			if err != nil {
				return nil, err
			}
		}
		if subject.Source != nil {
			return nil, gqlerror.Errorf("Dropping occurrences on sources right now")
		}
		a, err := b.getArtifact(ctx, &art)
		if err != nil {
			return nil, err
		}
		id, err := client.IsOccurrence.Create().
			SetPackage(p). // Should I be using SetPackageID() here?
			SetArtifact(a).
			SetJustification(occurrence.Justification).
			SetOrigin(occurrence.Origin).
			SetCollector(occurrence.Collector).
			OnConflict(
				entsql.ConflictColumns(
					isoccurrence.FieldPackageID,
					//isoccurrence.FieldSourceID,
					isoccurrence.FieldArtifactID,
					isoccurrence.FieldJustification,
					isoccurrence.FieldOrigin,
					isoccurrence.FieldCollector,
				),
			).
			UpdateNewValues().ID(ctx)
		if err != nil {
			return nil, err
		}
		return &id, nil
	})
	if err != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
	}

	// Upsert only gets ID, so need to query the object
	record, err := b.client.IsOccurrence.Query().
		Where(isoccurrence.ID(*recordID)).
		WithArtifact().
		WithPackage().
		Only(ctx)
	if err != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
	}

	return toModelIsOccurrence(ctx, record)
}

func toModelIsOccurrence(ctx context.Context, o *IsOccurrence) (*model.IsOccurrence, error) {
	var sub model.PackageOrSource
	if o.PackageID != 0 { // how do we indicate that this is linked to pkg and not src??
		top, err := pkgTreeFromVersion(ctx, o.Edges.Package)
		if err != nil {
			return nil, err
		}
		sub = toModelPackage(top)
	}
	// if o.SourceID != 0 { // ?? how do we do this?
	// 	sub = toModelSource(o.Edges.Source)
	// }
	return &model.IsOccurrence{
		ID:            nodeid(o.ID),
		Subject:       sub,
		Artifact:      toModelArtifact(o.Edges.Artifact),
		Justification: o.Justification,
		Origin:        o.Origin,
		Collector:     o.Collector,
	}, nil
}

func toModelIsDependency(ctx context.Context, id *IsDependency) (*model.IsDependency, error) {
	p, err := pkgTreeFromVersion(ctx, id.Edges.Package)
	if err != nil {
		return nil, err
	}
	dp, err := pkgTreeFromName(ctx, id.Edges.DependentPackage)
	if err != nil {
		return nil, err
	}
	return &model.IsDependency{
		ID:               nodeid(id.ID),
		Package:          toModelPackage(p),
		DependentPackage: toModelPackage(dp),
		VersionRange:     id.VersionRange,
		DependencyType:   model.DependencyType(id.DependencyType),
		Justification:    id.Justification,
		Origin:           id.Origin,
		Collector:        id.Collector,
	}, nil
}

func pkgVersionPreds(spec *model.PkgSpec) []predicate.PackageVersion {
	if spec == nil {
		return nil
	}
	rv := []predicate.PackageVersion{
		IDEQ(spec.ID),
		optionalPredicate(spec.Version, packageversion.Version),
		optionalPredicate(spec.Subpath, packageversion.Subpath),
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

	if spec.MatchOnlyEmptyQualifiers != nil && *spec.MatchOnlyEmptyQualifiers {
		rv = append(rv, packageversion.Qualifiers(""))
	} else if spec.Qualifiers != nil {
		// FIXME need to do custom filtering to allow specifying partial qualifiers? or key only??
		// query.Where(isdependency.HasPackageWith(packageversion.Qualifiers(qualifiersToString(isDependencySpec.Package.Qualifiers))))
	}

	return rv
}

func pkgNamePreds(spec *model.PkgNameSpec) []predicate.PackageName {
	if spec == nil {
		return nil
	}
	return []predicate.PackageName{
		IDEQ(spec.ID),
		optionalPredicate(spec.Name, packagename.Name),
		packagename.HasNamespaceWith(
			optionalPredicate(spec.Namespace, packagenamespace.Namespace),
			packagenamespace.HasPackageWith(
				optionalPredicate(spec.Type, packagenode.Type),
			),
		),
	}
}
