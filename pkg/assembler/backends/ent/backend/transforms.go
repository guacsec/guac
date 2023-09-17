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
	"fmt"

	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/dependency"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func toModelArtifact(a *ent.Artifact) *model.Artifact {
	return &model.Artifact{
		ID:        nodeID(a.ID),
		Algorithm: a.Algorithm,
		Digest:    a.Digest,
	}
}

func toModelBuilder(b *ent.Builder) *model.Builder {
	return &model.Builder{
		ID:  nodeID(b.ID),
		URI: b.URI,
	}
}

func toModelPackage(p *ent.PackageType) *model.Package {
	if p == nil {
		return nil
	}
	return &model.Package{
		ID:         nodeID(p.ID),
		Type:       p.Type,
		Namespaces: collect(p.Edges.Namespaces, toModelNamespace),
	}
}

func toModelNamespace(n *ent.PackageNamespace) *model.PackageNamespace {
	if n == nil {
		return nil
	}
	return &model.PackageNamespace{
		ID:        nodeID(n.ID),
		Namespace: n.Namespace,
		Names:     collect(n.Edges.Names, toModelPackageName),
	}
}

func toModelPackageName(n *ent.PackageName) *model.PackageName {
	if n == nil {
		return nil
	}
	return &model.PackageName{
		ID:       nodeID(n.ID),
		Name:     n.Name,
		Versions: collect(n.Edges.Versions, toModelPackageVersion),
	}
}

func toModelPackageVersion(v *ent.PackageVersion) *model.PackageVersion {

	return &model.PackageVersion{
		ID:         nodeID(v.ID),
		Version:    v.Version,
		Qualifiers: toPtrSlice(v.Qualifiers),
		Subpath:    v.Subpath,
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
	if len(out) == 0 {
		return nil
	}
	return out
}

func nodeID(id int) string {
	return fmt.Sprintf("%d", id)
}

func stringOrEmpty(s *string) string {
	return valueOrDefault(s, "")
}

func valueOrDefault[T any](v *T, def T) T {
	if v == nil {
		return def
	}
	return *v
}

func toModelIsOccurrenceWithSubject(o *ent.Occurrence) *model.IsOccurrence {
	return &model.IsOccurrence{
		ID:            nodeID(o.ID),
		Subject:       toOccurrenceSubject(o),
		Artifact:      toModelArtifact(o.Edges.Artifact),
		Justification: o.Justification,
		Origin:        o.Origin,
		Collector:     o.Collector,
	}
}

//func toModelIsOccurrence(o *ent.Occurrence, sub model.PackageOrSource) *model.IsOccurrence {
//	return &model.IsOccurrence{
//		ID:            nodeID(o.ID),
//		Subject:       sub,
//		Artifact:      toModelArtifact(o.Edges.Artifact),
//		Justification: o.Justification,
//		Origin:        o.Origin,
//		Collector:     o.Collector,
//	}
//}

func toOccurrenceSubject(oc *ent.Occurrence) model.PackageOrSource {
	if oc.Edges.Package != nil {
		return toModelPackage(backReferencePackageVersion(oc.Edges.Package))
	} else if oc.Edges.Source != nil &&
		// FIXME: (ivanvanderbyl) Refactor into backReferenceSubject(...)
		oc.Edges.Source.Edges.Namespace != nil &&
		oc.Edges.Source.Edges.Namespace.Edges.SourceType != nil {

		// Manually construct back references to avoid another 3 queries
		s := oc.Edges.Source
		ns := s.Edges.Namespace
		ns.Edges.Names = []*ent.SourceName{s}
		st := ns.Edges.SourceType
		st.Edges.Namespaces = []*ent.SourceNamespace{ns}
		return toModelSource(st)
	}
	return nil
}

//func pkgQualifierInputSpecToQuerySpec(input []*model.PackageQualifierInputSpec) []*model.PackageQualifierSpec {
//	if input == nil {
//		return nil
//	}
//	out := make([]*model.PackageQualifierSpec, len(input))
//	for i, in := range input {
//		out[i] = &model.PackageQualifierSpec{
//			Key:   in.Key,
//			Value: &in.Value,
//		}
//	}
//	return out
//}

func toModelIsDependencyWithBackrefs(id *ent.Dependency) *model.IsDependency {
	return toModelIsDependency(id, true)
}

//func toModelIsDependencyWithoutBackrefs(id *ent.Dependency) *model.IsDependency {
//	return toModelIsDependency(id, false)
//}

func toModelIsDependency(id *ent.Dependency, backrefs bool) *model.IsDependency {
	var pkg *model.Package
	var depPkg *model.Package
	if backrefs {
		pkg = toModelPackage(backReferencePackageVersion(id.Edges.Package))
		if id.Edges.DependentPackageName != nil {
			depPkg = toModelPackage(backReferencePackageName(id.Edges.DependentPackageName))
			// in this case, the expected response is package name with an empty package version array
			depPkg.Namespaces[0].Names[0].Versions = []*model.PackageVersion{}
		} else {
			depPkg = toModelPackage(backReferencePackageVersion(id.Edges.DependentPackageVersion))
		}
	} else {
		pkg = toModelPackage(id.Edges.Package.Edges.Name.Edges.Namespace.Edges.Package)
		if id.Edges.DependentPackageName != nil {
			depPkg = toModelPackage(id.Edges.DependentPackageName.Edges.Namespace.Edges.Package)
			// in this case, the expected response is package name with an empty package version array
			depPkg.Namespaces[0].Names[0].Versions = []*model.PackageVersion{}
		} else {
			depPkg = toModelPackage(id.Edges.DependentPackageVersion.Edges.Name.Edges.Namespace.Edges.Package)
		}
	}

	return &model.IsDependency{
		ID:               nodeID(id.ID),
		Package:          pkg,
		DependentPackage: depPkg,
		VersionRange:     id.VersionRange,
		DependencyType:   dependencyTypeFromEnum(id.DependencyType),
		Justification:    id.Justification,
		Origin:           id.Origin,
		Collector:        id.Collector,
	}
}

func dependencyTypeFromEnum(t dependency.DependencyType) model.DependencyType {
	switch t {
	case dependency.DependencyTypeDIRECT:
		return model.DependencyTypeDirect
	case dependency.DependencyTypeINDIRECT:
		return model.DependencyTypeIndirect
	default:
		return model.DependencyTypeUnknown
	}
}

func toModelHasSBOM(sbom *ent.BillOfMaterials) *model.HasSbom {
	return &model.HasSbom{
		ID:               nodeID(sbom.ID),
		Subject:          toPackageOrArtifact(sbom.Edges.Package, sbom.Edges.Artifact),
		URI:              sbom.URI,
		Algorithm:        sbom.Algorithm,
		Digest:           sbom.Digest,
		DownloadLocation: sbom.DownloadLocation,
		Origin:           sbom.Origin,
		Collector:        sbom.Collector,
	}
}

func toPackageOrArtifact(p *ent.PackageVersion, a *ent.Artifact) model.PackageOrArtifact {
	if p != nil {
		return toModelPackage(backReferencePackageVersion(p))
	} else if a != nil {
		return toModelArtifact(a)
	}
	return nil
}
