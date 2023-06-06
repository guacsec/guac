package ent

import (
	"fmt"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func toModelArtifact(a *Artifact) *model.Artifact {
	return &model.Artifact{
		ID:        nodeid(a.ID),
		Algorithm: a.Algorithm,
		Digest:    a.Digest,
	}
}

func toModelBuilder(b *BuilderNode) *model.Builder {
	return &model.Builder{
		ID:  nodeid(b.ID),
		URI: b.URI,
	}
}

func toModelPackage(p *PackageNode) *model.Package {
	return &model.Package{
		ID:         nodeid(p.ID),
		Type:       p.Type,
		Namespaces: collect(p.Edges.Namespaces, toModelNamespace),
	}
}

func toModelNamespace(n *PackageNamespace) *model.PackageNamespace {
	return &model.PackageNamespace{
		ID:        nodeid(n.ID),
		Namespace: n.Namespace,
		Names:     collect(n.Edges.Names, toModelPackageName),
	}
}

func toModelPackageName(n *PackageName) *model.PackageName {
	return &model.PackageName{
		ID:       nodeid(n.ID),
		Name:     n.Name,
		Versions: collect(n.Edges.Versions, toModelPackageVersion),
	}
}

func toModelPackageVersion(v *PackageVersion) *model.PackageVersion {
	return &model.PackageVersion{
		ID:      nodeid(v.ID),
		Version: v.Version,
		// Qualifiers: []*model.PackageQualifier{},
		// Subpath:    v.Subpath,
	}
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

func nodeid(id int) string {
	return fmt.Sprintf("%d", id)
}
