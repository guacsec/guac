package helpers

import (
	"fmt"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func UpdatePurlForNamespaces(packageObj *model.Package) ([]*model.PackageNamespace, error) {
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
				version.Purl = fmt.Sprintf("pkg:%s/%s/%s", packageObj.Type, namespace.Namespace, name.Name)
			}
		}
		modifiedNamespace.Names = names
		updatedNamespaces[i] = modifiedNamespace
	}

	return updatedNamespaces, nil
}