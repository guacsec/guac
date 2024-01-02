package helpers

import "github.com/guacsec/guac/pkg/assembler/graphql/model"

func UpdatePurlForPackageNamespaces(packageObj *model.Package) ([]*model.PackageNamespace, error) {
	updatedNamespaces := make([]*model.PackageNamespace, len(packageObj.Namespaces))

	for i, namespace := range packageObj.Namespaces {
		modifiedNamespace := &model.PackageNamespace{
			ID:        namespace.ID,
			Namespace: namespace.Namespace,
		}
		names := make([]*model.PackageName, len(namespace.Names))
		for j, name := range namespace.Names {
			names[j] = name
			versions := make([]*model.PackageVersion, len(name.Versions))
			for k, version := range name.Versions {
				versions[k] = version

				var qualifiers []string
				for _, qualifier := range version.Qualifiers {
					qualifiers = append(qualifiers, qualifier.Key)//, qualifier.Value)
					qualifiers = append(qualifiers, qualifier.Value)
				}
				version.Purl = PkgToPurl(packageObj.Type,  namespace.Namespace, name.Name, version.Version, version.Subpath, qualifiers)
			}
		}
		modifiedNamespace.Names = names
		updatedNamespaces[i] = modifiedNamespace
	}

	return updatedNamespaces, nil
}
