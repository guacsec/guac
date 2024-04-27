//
// Copyright 2024 The GUAC Authors.
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

package helpers

import (
	"context"
	"fmt"

	"github.com/Khan/genqlient/graphql"
	gql "github.com/guacsec/guac/pkg/assembler/clients/generated"
	assembler_helpers "github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/logging"
)

// Returns all of the version nodes of the AllPkgTree fragment input
func GetVersionsOfAllPackageTree(trie gql.AllPkgTree) []gql.AllPkgTreeNamespacesPackageNamespaceNamesPackageNameVersionsPackageVersion {
	res := []gql.AllPkgTreeNamespacesPackageNamespaceNamesPackageNameVersionsPackageVersion{}
	for _, namespace := range trie.GetNamespaces() {
		for _, name := range namespace.GetNames() {
			res = append(res, name.GetVersions()...)
		}
	}
	return res
}

// Returns all of the version nodes of the Packages query result
func GetVersionsOfPackagesResponse(packages []gql.PackagesPackagesPackage) []gql.AllPkgTreeNamespacesPackageNamespaceNamesPackageNameVersionsPackageVersion {
	res := []gql.AllPkgTreeNamespacesPackageNamespaceNamesPackageNameVersionsPackageVersion{}
	for _, pkg := range packages {
		res = append(res, GetVersionsOfAllPackageTree(pkg.AllPkgTree)...)
	}
	return res
}

// Returns the version node of the package that matches the input purl. The purl
// must uniquely identify a package, otherwise an error is returned.
func FindPackageWithPurl(ctx context.Context, gqlClient graphql.Client,
	purl string) (gql.AllPkgTreeNamespacesPackageNamespaceNamesPackageNameVersionsPackageVersion, error) {
	logger := logging.FromContext(ctx)

	filter, err := assembler_helpers.PurlToPkgFilter(purl)
	if err != nil {
		// return the error message, to indicate unparseable purls
		return gql.AllPkgTreeNamespacesPackageNamespaceNamesPackageNameVersionsPackageVersion{}, err
	}
	response, err := gql.Packages(ctx, gqlClient, filter)
	if err != nil {
		logger.Errorf(fmt.Sprintf("Packages query returned error: %v", err))
		return gql.AllPkgTreeNamespacesPackageNamespaceNamesPackageNameVersionsPackageVersion{}, Err502
	}

	versions := GetVersionsOfPackagesResponse(response.GetPackages())
	if len(versions) == 0 {
		return gql.AllPkgTreeNamespacesPackageNamespaceNamesPackageNameVersionsPackageVersion{}, fmt.Errorf("no packages matched the input purl")
	}
	// The filter should have matched at most one package
	return response.GetPackages()[0].AllPkgTree.GetNamespaces()[0].GetNames()[0].GetVersions()[0], nil
}
