package backend

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagenamespace"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagenode"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
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

func getPkgName(ctx context.Context, client *ent.Client, pkgin *model.PkgInputSpec) (*ent.PackageName, error) {
	return client.PackageNode.Query().
		Where(packagenode.Type(pkgin.Type)).
		QueryNamespaces().Where(packagenamespace.Namespace(valueOrDefault(pkgin.Namespace, ""))).
		QueryNames().Where(packagename.Name(pkgin.Name)).
		Only(ctx)
}

func getPkgVersion(ctx context.Context, client *ent.Client, pkgin *model.PkgInputSpec) (*ent.PackageVersion, error) {
	return client.PackageNode.Query().
		Where(packagenode.Type(pkgin.Type)).
		QueryNamespaces().Where(packagenamespace.Namespace(valueOrDefault(pkgin.Namespace, ""))).
		QueryNames().Where(packagename.Name(pkgin.Name)).
		QueryVersions().
		Where(
			optionalPredicate(pkgin.Version, packageversion.VersionEQ),
			optionalPredicate(pkgin.Subpath, packageversion.SubpathEQ),
			packageversion.QualifiersMatchSpec(pkgQualifierInputSpecToQuerySpec(pkgin.Qualifiers)),
		).
		Only(ctx)

	// return client.PackageVersion.Query().
	// 	Where(
	// 		optionalPredicate(pkgin.Version, packageversion.VersionEQ),
	// 		optionalPredicate(pkgin.Subpath, packageversion.SubpathEQ),
	// 		packageversion.QualifiersMatchSpec(pkgQualifierInputSpecToQuerySpec(pkgin.Qualifiers)),
	// 		packageversion.HasNameWith(
	// 			packagename.Name(pkgin.Name),
	// 			packagename.HasNamespaceWith(
	// 				packagenamespace.Namespace(valueOrDefault(pkgin.Namespace, "")),
	// 				packagenamespace.HasPackageWith(
	// 					packagenode.Type(pkgin.Type),
	// 				),
	// 			),
	// 		),
	// 	).
	// 	Only(ctx)
}

func getArtifact(ctx context.Context, client *ent.Client, artin *model.ArtifactInputSpec) (*ent.Artifact, error) {
	return client.Artifact.Query().
		Where(artifact.Algorithm(artin.Algorithm), artifact.Digest(artin.Digest)).
		Only(ctx)
}

// When verb nodes point to a PackageName/Version or SourceName we need to
// rebuild the full top level tree object with just the nested objects that are
// part of the path to that node

func pkgTreeFromVersion(ctx context.Context, pv *ent.PackageVersion) (*ent.PackageNode, error) {
	// pv.QueryName().QueryNamespace().QueryPackage().Query

	// eagerLoadedVersion, err := pv.
	// 	QueryName().
	// 	WithNamespace().
	// 	QueryNamespace().
	// 	WithPackage().
	// 	QueryPackage().
	// 	WithNamespaces(func(q *ent.PackageNamespaceQuery) {
	// 		q.WithNames(func(q *ent.PackageNameQuery) {
	// 			q.WithVersions()
	// 		})
	// 	}).
	// 	Only(ctx)
	// if err != nil {
	// 	return nil, err
	// }

	// return eagerLoadedVersion, nil

	n, err := pv.QueryName().Only(ctx)
	if err != nil {
		return nil, err
	}
	ns, err := n.QueryNamespace().Only(ctx)
	if err != nil {
		return nil, err
	}

	return ns.QueryPackage().
		WithNamespaces(func(q *ent.PackageNamespaceQuery) {
			q.Where(packagenamespace.Namespace(ns.Namespace))
			q.WithNames(func(q *ent.PackageNameQuery) {
				q.Where(packagename.Name(n.Name))
				q.WithVersions(func(q *ent.PackageVersionQuery) {
					q.Where(packageversion.Hash(hashPackageVersion(pv.Version, pv.Subpath, pv.Qualifiers)))
				})
			})
		}).
		Only(ctx)
}

func pkgTreeFromName(ctx context.Context, pn *ent.PackageName) (*ent.PackageNode, error) {
	ns, err := pn.QueryNamespace().Only(ctx)
	if err != nil {
		return nil, err
	}
	return ns.QueryPackage().
		WithNamespaces(func(q *ent.PackageNamespaceQuery) {
			q.Where(packagenamespace.Namespace(ns.Namespace))
			q.WithNames(func(q *ent.PackageNameQuery) {
				q.Where(packagename.Name(pn.Name))
			})
		}).
		Only(ctx)
}
