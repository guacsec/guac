package helpers

import (
	"context"
	"github.com/Khan/genqlient/graphql"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	gen "github.com/guacsec/guac/pkg/guacrest/generated"
)

func GetInfoForPackage(ctx context.Context, gqlClient graphql.Client, pkgInput *model.PkgInputSpec, searchVulns *bool) (*gen.PackageInfoResponseJSONResponse, error) {
	response := gen.PackageInfoResponseJSONResponse{}

	var packages []gen.PackageInfo

	pkgSpec := model.PkgSpec{
		Type: &pkgInput.Type,
		Name: &pkgInput.Name,
	}

	if *pkgInput.Namespace != "" {
		pkgSpec.Namespace = pkgInput.Namespace
	}
	if *pkgInput.Version != "" {
		pkgSpec.Version = pkgInput.Version
	}
	if *pkgInput.Subpath != "" {
		pkgSpec.Subpath = pkgInput.Subpath
	}

	pkgs, err := model.Packages(ctx, gqlClient, pkgSpec)
	if err != nil {
		return nil, err
	}

	for _, pkg := range pkgs.Packages {
		for _, namespace := range pkg.Namespaces {
			for _, n := range namespace.Names {
				for _, v := range n.Versions {
					qualifiers := map[string]string{}

					for _, qualifier := range v.Qualifiers {
						qualifiers[qualifier.Key] = qualifier.Value
					}

					packages = append(packages, gen.PackageInfo{
						Type:       &pkg.Type,
						Name:       &n.Name,
						Namespace:  &namespace.Namespace,
						Version:    &v.Version,
						Purl:       &v.Purl,
						Subpath:    &v.Subpath,
						Qualifiers: &qualifiers,
					})
				}
			}
		}
	}
	response.Packages = &packages
	return &response, nil
}
