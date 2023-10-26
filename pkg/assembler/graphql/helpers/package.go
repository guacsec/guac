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

package helpers

import (
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// Return a package structure containing only IDs
func GetPackageAsIds(packages []*model.Package) []*model.PackageIDs {
	results := []*model.PackageIDs{}
	for _, pkg := range packages {
		resultPackage := model.PackageIDs{PackageTypeID: pkg.ID}
		for _, namespace := range pkg.Namespaces {
			resultNamespace := resultPackage
			resultNamespace.PackageNamespaceID = namespace.ID
			for _, name := range namespace.Names {
				resultName := resultNamespace
				resultName.PackageNameID = name.ID
				for _, version := range name.Versions {
					resultVersion := resultName
					resultVersion.PackageVersionID = version.ID
					results = append(results, &resultVersion)
				}
			}
		}
	}
	return results
}

// Return a source structure containing only IDs
func GetSourceAsIds(sources []*model.Source) []*model.SourceIDs {
	results := []*model.SourceIDs{}
	for _, src := range sources {
		resultSource := model.SourceIDs{SourceTypeID: src.ID}
		for _, namespace := range src.Namespaces {
			resultNamespace := resultSource
			resultNamespace.SourceNamespaceID = namespace.ID
			for _, name := range namespace.Names {
				resultName := resultNamespace
				resultName.SourceNameID = name.ID
				results = append(results, &resultName)
			}
		}
	}
	return results
}
