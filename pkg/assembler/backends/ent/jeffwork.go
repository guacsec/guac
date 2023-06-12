package ent

import (
	"context"

	entsql "entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/isoccurrence"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagenamespace"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagenode"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
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
