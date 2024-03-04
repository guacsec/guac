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

package helper

import (
	"slices"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func SortAndRemoveDups(ids []string) []string {
	numIDs := len(ids)
	if numIDs > 1 {
		slices.Sort(ids)
		nextIndex := 1
		for index := 1; index < numIDs; index++ {
			currentVal := ids[index]
			if ids[index-1] != currentVal {
				ids[nextIndex] = currentVal
				nextIndex++
			}
		}
		ids = ids[:nextIndex]
	}
	return ids
}

func GetPackageAndArtifactFilters(filters []*model.PackageOrArtifactSpec) (pkgs []*model.PkgSpec, arts []*model.ArtifactSpec) {
	for _, pkgOrArtSpec := range filters {
		if pkgOrArtSpec.Package != nil {
			pkgs = append(pkgs, pkgOrArtSpec.Package)
		} else if pkgOrArtSpec.Artifact != nil {
			arts = append(arts, pkgOrArtSpec.Artifact)
		}
	}
	return
}

// IDs should be sorted
func IsIDPresent(id string, linkIDs []string) bool {
	_, found := slices.BinarySearch[[]string](linkIDs, id)
	return found
}
