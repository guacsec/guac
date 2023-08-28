package backend

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagenamespace"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
)

//func getArtifact(ctx context.Context, client *ent.Client, artin *model.ArtifactInputSpec) (*ent.Artifact, error) {
//	return client.Artifact.Query().
//		Where(artifact.Algorithm(artin.Algorithm), artifact.Digest(artin.Digest)).
//		Only(ctx)
//}

// When verb nodes point to a PackageName/Version or SourceName we need to
// rebuild the full top level tree object with just the nested objects that are
// part of the path to that node

func pkgTreeFromVersion(ctx context.Context, pv *ent.PackageVersion) (*ent.PackageType, error) {
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

	q := ns.QueryPackage()
	buildPackageTreeQuery(q, ns.Namespace, n.Name, pv)
	return q.Only(ctx)
}

func buildPackageTreeQuery(q *ent.PackageTypeQuery, ns, packageName string, pv *ent.PackageVersion) {
	q.WithNamespaces(func(q *ent.PackageNamespaceQuery) {
		q.Where(packagenamespace.Namespace(ns))
		q.WithNames(func(q *ent.PackageNameQuery) {
			q.Where(packagename.Name(packageName))
			q.WithVersions(func(q *ent.PackageVersionQuery) {
				q.Where(packageversion.Hash(hashPackageVersion(pv.Version, pv.Subpath, pv.Qualifiers)))
			})
		})
	})
}

//func pkgTreeFromName(ctx context.Context, pn *ent.PackageName) (*ent.PackageType, error) {
//	ns, err := pn.QueryNamespace().Only(ctx)
//	if err != nil {
//		return nil, err
//	}
//	return ns.QueryPackage().
//		WithNamespaces(func(q *ent.PackageNamespaceQuery) {
//			q.Where(packagenamespace.Namespace(ns.Namespace))
//			q.WithNames(func(q *ent.PackageNameQuery) {
//				q.Where(packagename.Name(pn.Name))
//			})
//		}).
//		Only(ctx)
//}
