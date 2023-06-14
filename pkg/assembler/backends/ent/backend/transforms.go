package backend

import (
	"context"
	"fmt"
	"net/url"

	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagenamespace"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func toModelArtifact(a *ent.Artifact) *model.Artifact {
	return &model.Artifact{
		ID:        nodeID(a.ID),
		Algorithm: a.Algorithm,
		Digest:    a.Digest,
	}
}

func toModelBuilder(b *ent.BuilderNode) *model.Builder {
	return &model.Builder{
		ID:  nodeID(b.ID),
		URI: b.URI,
	}
}

func toModelPackage(p *ent.PackageNode) *model.Package {
	return &model.Package{
		ID:         nodeID(p.ID),
		Type:       p.Type,
		Namespaces: collect(p.Edges.Namespaces, toModelNamespace),
	}
}

func toModelNamespace(n *ent.PackageNamespace) *model.PackageNamespace {
	return &model.PackageNamespace{
		ID:        nodeID(n.ID),
		Namespace: n.Namespace,
		Names:     collect(n.Edges.Names, toModelPackageName),
	}
}

func toModelPackageName(n *ent.PackageName) *model.PackageName {
	return &model.PackageName{
		ID:       nodeID(n.ID),
		Name:     n.Name,
		Versions: collect(n.Edges.Versions, toModelPackageVersion),
	}
}

func toModelSource(s *ent.Source) *model.Source {
	return &model.Source{
		ID:   nodeID(s.ID),
		Type: s.Type,
		Namespaces: collect(s.Edges.Namespaces, func(n *ent.SourceNamespace) *model.SourceNamespace {
			return &model.SourceNamespace{
				ID:        nodeID(n.ID),
				Namespace: n.Namespace,
				Names: collect(n.Edges.Names, func(n *ent.SourceName) *model.SourceName {
					return &model.SourceName{
						ID:     nodeID(n.ID),
						Name:   n.Name,
						Tag:    &n.Tag,
						Commit: &n.Commit,
					}
				}),
			}
		}),
	}
}

func toModelPackageVersion(v *ent.PackageVersion) *model.PackageVersion {
	qualifiers := []*model.PackageQualifier{}

	vals, err := url.ParseQuery(v.Qualifiers)
	if err == nil {
		for k, v := range vals {
			qualifiers = append(qualifiers, &model.PackageQualifier{
				Key:   k,
				Value: v[0],
			})
		}
	}

	return &model.PackageVersion{
		ID:         nodeID(v.ID),
		Version:    v.Version,
		Qualifiers: qualifiers,
		Subpath:    v.Subpath,
	}
}

func (e *EntBackend) buildPackageResponse(ctx context.Context, id int, filter model.PkgSpec) (*model.Package, error) {
	// e.client.PackageNode.Query().
	// 	Where().
	// 	WithNamespaces(func(q *ent.PackageNamespaceQuery) {
	// 		q.Where(optionalPredicate(filter.Namespace, packagenamespace.NamespaceEQ))
	// 		q.WithNames(func(q *ent.PackageNameQuery) {
	// 			q.Where(optionalPredicate(filter.Name, packagename.NameEQ))
	// 			q.WithVersions(func(q *ent.PackageVersionQuery) {
	// 				q.Where(optionalPredicate(filter.Version, packageversion.VersionEQ))
	// 				q.Where(optionalPredicate(filter.Subpath, packageversion.SubpathEQ))
	// 			})
	// 		})
	// 	})

	// Version
	records, err := e.client.PackageVersion.Query().
		Where(
			optionalPredicate(filter.ID, IDEQ),
			optionalPredicate(filter.Version, packageversion.VersionEQ),
			optionalPredicate(filter.Subpath, packageversion.SubpathEQ),
		).
		All(ctx)

	if err != nil {
		return nil, err
	}

	if len(records) == 0 {
		return nil, nil
	}

	// if filter.Name == nil {
	// 	return nil, nil
	// }
	pvl := collect(records, toModelPackageVersion)

	// Name
	pnl := []*model.PackageName{}
	nameRecord, err := e.client.PackageName.Query().Where(optionalPredicate(filter.Name, packagename.NameEQ)).Only(ctx)
	if err != nil {
		return nil, err
	}
	name := toModelPackageName(nameRecord)
	name.Versions = pvl
	pnl = append(pnl, name)

	// Namespace
	pnsl := []*model.PackageNamespace{}
	nsRecord, err := nameRecord.QueryNamespace().Where(optionalPredicate(filter.Namespace, packagenamespace.NamespaceEQ)).Only(ctx)
	if err != nil {
		return nil, err
	}
	ns := toModelNamespace(nsRecord)
	ns.Names = pnl
	pnsl = append(pnsl, ns)

	// Package
	pkg, err := nsRecord.QueryPackage().Only(ctx)
	if err != nil {
		return nil, err
	}
	p := &model.Package{
		ID:         nodeID(pkg.ID),
		Type:       pkg.Type,
		Namespaces: pnsl,
	}

	return p, nil
}

// collect is a simple helper to transform collections of a certain type to another type
// using the transform function func(T) R
func collect[T any, R any](items []T, transformer func(T) R) []R {
	if items == nil {
		return nil
	}

	out := make([]R, len(items))
	for i, item := range items {
		out[i] = transformer(item)
	}
	return out
}

func collectWithError[T any, R any](ctx context.Context, items []T, transformer func(context.Context, T) (R, error)) ([]R, error) {
	if items == nil {
		return nil, nil
	}

	out := make([]R, len(items))
	for i, item := range items {
		t, err := transformer(ctx, item)
		if err != nil {
			return nil, err
		}
		out[i] = t
	}
	return out, nil
}

func nodeID(id int) string {
	return fmt.Sprintf("%d", id)
}

func valueOrDefault[T any](v *T, def T) T {
	if v == nil {
		return def
	}
	return *v
}

func qualifiersToString(qualifiers []*model.PackageQualifierInputSpec) string {
	if qualifiers == nil {
		return ""
	}

	qs := url.Values{}
	for _, q := range qualifiers {
		qs.Add(q.Key, q.Value)
	}

	return qs.Encode()
}

func packageToModelPackage(p *ent.PackageNode) *model.Package {
	return &model.Package{
		ID:         nodeID(p.ID),
		Type:       p.Type,
		Namespaces: collect(p.Edges.Namespaces, toModelNamespace),
	}
}

func packageNamespaceToModelPackage(n *ent.PackageNamespace) *model.Package {
	return &model.Package{
		ID:         nodeID(n.ID),
		Type:       n.Edges.Package.Type,
		Namespaces: []*model.PackageNamespace{toModelNamespace(n)},
	}
}

func packageVersionToModelPackage(pv *ent.PackageVersion) *model.Package {
	return &model.Package{
		ID:         nodeID(pv.ID),
		Type:       pv.Edges.Name.Edges.Namespace.Edges.Package.Type,
		Namespaces: []*model.PackageNamespace{toModelNamespace(pv.Edges.Name.Edges.Namespace)},
	}
}

func toModelIsOccurrence(o *ent.Occurrence, sub model.PackageOrSource) *model.IsOccurrence {
	return &model.IsOccurrence{
		ID:            nodeID(o.ID),
		Subject:       sub,
		Artifact:      toModelArtifact(o.Edges.Artifact),
		Justification: o.Justification,
		Origin:        o.Origin,
		Collector:     o.Collector,
	}
}
