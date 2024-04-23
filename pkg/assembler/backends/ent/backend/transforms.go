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
	"strings"

	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/billofmaterials"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/builder"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifylegal"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/dependency"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/license"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/occurrence"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func toModelArtifact(a *ent.Artifact) *model.Artifact {
	return &model.Artifact{
		ID:        toGlobalID(artifact.Table, a.ID.String()),
		Algorithm: a.Algorithm,
		Digest:    a.Digest,
	}
}

func toModelBuilder(b *ent.Builder) *model.Builder {
	return &model.Builder{
		ID:  toGlobalID(builder.Table, b.ID.String()),
		URI: b.URI,
	}
}

func toModelPackageTrie(collectedPkgNames []*ent.PackageName) []*model.Package {
	pkgTypes := map[string]map[string]map[string][]*model.PackageVersion{}

	for _, pkgName := range collectedPkgNames {
		nameString := pkgName.Name + "," + toGlobalID(packagename.Table, pkgName.ID.String())

		namespaceString := pkgName.Namespace + "," + toGlobalID(pkgNamespaceString, strings.Join([]string{pkgName.Type, pkgName.Namespace}, guacIDSplit))
		typeString := pkgName.Type + "," + toGlobalID(pkgTypeString, pkgName.Type)

		if pkgNamespaces, ok := pkgTypes[typeString]; ok {
			if pkgNames, ok := pkgNamespaces[namespaceString]; ok {
				pkgNames[nameString] = append(pkgNames[nameString], collect(pkgName.Edges.Versions, toModelPackageVersion)...)
			} else {
				pkgNames := map[string][]*model.PackageVersion{}
				pkgNames[nameString] = append(pkgNames[nameString], collect(pkgName.Edges.Versions, toModelPackageVersion)...)
				pkgNamespaces[namespaceString] = pkgNames
				pkgTypes[typeString] = pkgNamespaces
			}
		} else {
			pkgNames := map[string][]*model.PackageVersion{}
			pkgNames[nameString] = append(pkgNames[nameString], collect(pkgName.Edges.Versions, toModelPackageVersion)...)
			pkgNamespaces := map[string]map[string][]*model.PackageVersion{}
			pkgNamespaces[namespaceString] = pkgNames
			pkgTypes[typeString] = pkgNamespaces
		}
	}
	var packages []*model.Package
	for pkgType, pkgNamespaces := range pkgTypes {
		collectedPkgNamespaces := []*model.PackageNamespace{}
		for namespace, pkgNames := range pkgNamespaces {
			var collectedPkgNames []*model.PackageName
			for name, versions := range pkgNames {
				nameValues := strings.Split(name, ",")
				pkgName := &model.PackageName{
					ID:       nameValues[1],
					Name:     nameValues[0],
					Versions: versions,
				}
				collectedPkgNames = append(collectedPkgNames, pkgName)
			}
			namespaceValues := strings.Split(namespace, ",")
			pkgNamespace := &model.PackageNamespace{
				ID:        namespaceValues[1],
				Namespace: namespaceValues[0],
				Names:     collectedPkgNames,
			}
			collectedPkgNamespaces = append(collectedPkgNamespaces, pkgNamespace)
		}
		typeValues := strings.Split(pkgType, ",")
		collectedPackage := &model.Package{
			ID:         typeValues[1],
			Type:       typeValues[0],
			Namespaces: collectedPkgNamespaces,
		}
		packages = append(packages, collectedPackage)
	}

	return packages
}

func toModelPackage(p *ent.PackageName) *model.Package {
	if p == nil {
		return nil
	}
	return &model.Package{
		ID:         toGlobalID(pkgTypeString, p.Type),
		Type:       p.Type,
		Namespaces: collect([]*ent.PackageName{p}, toModelNamespace),
	}
}

func toModelNamespace(n *ent.PackageName) *model.PackageNamespace {
	if n == nil {
		return nil
	}
	return &model.PackageNamespace{
		ID:        toGlobalID(pkgNamespaceString, strings.Join([]string{n.Type, n.Namespace}, guacIDSplit)),
		Namespace: n.Namespace,
		Names:     collect([]*ent.PackageName{n}, toModelPackageName),
	}
}

func toModelPackageName(n *ent.PackageName) *model.PackageName {
	if n == nil {
		return nil
	}
	return &model.PackageName{
		ID:       toGlobalID(packagename.Table, n.ID.String()),
		Name:     n.Name,
		Versions: collect(n.Edges.Versions, toModelPackageVersion),
	}
}

func toModelPackageVersion(v *ent.PackageVersion) *model.PackageVersion {

	return &model.PackageVersion{
		ID:         toGlobalID(packageversion.Table, v.ID.String()),
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

// func nodeID(id int) string {
// 	return fmt.Sprintf("%d", id)
// }

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
		ID:            toGlobalID(occurrence.Table, o.ID.String()),
		Subject:       toModelPackageOrSource(o.Edges.Package, o.Edges.Source),
		Artifact:      toModelArtifact(o.Edges.Artifact),
		Justification: o.Justification,
		Origin:        o.Origin,
		Collector:     o.Collector,
		DocumentRef:   o.DocumentRef,
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
		pkg = toModelPackage(id.Edges.Package.Edges.Name)
		if id.Edges.DependentPackageName != nil {
			depPkg = toModelPackage(id.Edges.DependentPackageName)
			// in this case, the expected response is package name with an empty package version array
			depPkg.Namespaces[0].Names[0].Versions = []*model.PackageVersion{}
		} else {
			depPkg = toModelPackage(id.Edges.DependentPackageVersion.Edges.Name)
		}
	}

	return &model.IsDependency{
		ID:                toGlobalID(dependency.Table, id.ID.String()),
		Package:           pkg,
		DependencyPackage: depPkg,
		VersionRange:      id.VersionRange,
		DependencyType:    dependencyTypeFromEnum(id.DependencyType),
		Justification:     id.Justification,
		Origin:            id.Origin,
		Collector:         id.Collector,
		DocumentRef:       id.DocumentRef,
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
		ID:                   toGlobalID(billofmaterials.Table, sbom.ID.String()),
		Subject:              toPackageOrArtifact(sbom.Edges.Package, sbom.Edges.Artifact),
		URI:                  sbom.URI,
		Algorithm:            sbom.Algorithm,
		Digest:               sbom.Digest,
		DownloadLocation:     sbom.DownloadLocation,
		Origin:               sbom.Origin,
		Collector:            sbom.Collector,
		DocumentRef:          sbom.DocumentRef,
		KnownSince:           sbom.KnownSince,
		IncludedSoftware:     toIncludedSoftware(sbom.Edges.IncludedSoftwarePackages, sbom.Edges.IncludedSoftwareArtifacts),
		IncludedDependencies: collect(sbom.Edges.IncludedDependencies, toModelIsDependencyWithBackrefs),
		IncludedOccurrences:  collect(sbom.Edges.IncludedOccurrences, toModelIsOccurrenceWithSubject),
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

func toIncludedSoftware(pkgs []*ent.PackageVersion, artifacts []*ent.Artifact) []model.PackageOrArtifact {
	var result []model.PackageOrArtifact
	for i := range pkgs {
		result = append(result, toModelPackage(backReferencePackageVersion(pkgs[i])))
	}
	for i := range artifacts {
		result = append(result, toModelArtifact(artifacts[i]))
	}
	return result
}

func toModelLicense(entLicense *ent.License) *model.License {

	var dbInLine *string
	if entLicense.Inline != "" {
		dbInLine = ptrfrom.String(entLicense.Inline)
	}
	var dbListVersion *string
	if entLicense.ListVersion != "" {
		dbListVersion = ptrfrom.String(entLicense.ListVersion)
	}

	return &model.License{
		ID:          toGlobalID(license.Table, entLicense.ID.String()),
		Name:        entLicense.Name,
		Inline:      dbInLine,
		ListVersion: dbListVersion,
	}
}

func toModelCertifyLegal(cl *ent.CertifyLegal) *model.CertifyLegal {
	return &model.CertifyLegal{
		ID:                 toGlobalID(certifylegal.Table, cl.ID.String()),
		Subject:            toModelPackageOrSource(cl.Edges.Package, cl.Edges.Source),
		DeclaredLicense:    cl.DeclaredLicense,
		DeclaredLicenses:   collect(cl.Edges.DeclaredLicenses, toModelLicense),
		DiscoveredLicense:  cl.DiscoveredLicense,
		DiscoveredLicenses: collect(cl.Edges.DiscoveredLicenses, toModelLicense),
		Attribution:        cl.Attribution,
		Justification:      cl.Justification,
		TimeScanned:        cl.TimeScanned,
		Origin:             cl.Origin,
		Collector:          cl.Collector,
		DocumentRef:        cl.DocumentRef,
	}
}

func toModelPackageOrSource(pkg *ent.PackageVersion, src *ent.SourceName) model.PackageOrSource {
	if pkg != nil {
		return toModelPackage(backReferencePackageVersion(pkg))
	} else if src != nil {
		return toModelSource(src)
	}
	return nil
}
