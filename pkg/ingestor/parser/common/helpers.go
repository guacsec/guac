//
// Copyright 2022 The GUAC Authors.
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

package common

import (
	"reflect"

	"github.com/guacsec/guac/pkg/assembler"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
)

// TODO: change the DependencyType based on the relationship
func GetIsDep(foundNode *model.PkgInputSpec, relatedPackNodes []*model.PkgInputSpec, relatedFileNodes []*model.PkgInputSpec, justification string) (*assembler.IsDependencyIngest, error) {
	if len(relatedFileNodes) > 0 {
		for _, rfileNode := range relatedFileNodes {
			// TODO: Check is this always just expected to be one?
			return &assembler.IsDependencyIngest{
				Pkg:    foundNode,
				DepPkg: rfileNode,
				IsDependency: &model.IsDependencyInputSpec{
					DependencyType: model.DependencyTypeDirect,
					Justification:  justification,
					VersionRange:   *rfileNode.Version,
				},
			}, nil
		}
	} else if len(relatedPackNodes) > 0 {
		for _, rpackNode := range relatedPackNodes {
			return &assembler.IsDependencyIngest{
				Pkg:    foundNode,
				DepPkg: rpackNode,
				IsDependency: &model.IsDependencyInputSpec{
					DependencyType: model.DependencyTypeDirect,
					Justification:  justification,
					VersionRange:   *rpackNode.Version,
				},
			}, nil

		}
	}
	return nil, nil
}

// TODO: change the DependencyType based on the relationship
func CreateTopLevelIsDeps(toplevel *model.PkgInputSpec, packages map[string][]*model.PkgInputSpec, files map[string][]*model.PkgInputSpec, justification string) []assembler.IsDependencyIngest {
	isDeps := []assembler.IsDependencyIngest{}
	for _, packNodes := range packages {
		for _, packNode := range packNodes {
			if !reflect.DeepEqual(packNode, toplevel) {
				p := assembler.IsDependencyIngest{
					Pkg:    toplevel,
					DepPkg: packNode,
					IsDependency: &model.IsDependencyInputSpec{
						DependencyType: model.DependencyTypeDirect,
						Justification:  justification,
						VersionRange:   *packNode.Version,
					},
				}
				isDeps = append(isDeps, p)
			}
		}
	}

	for _, fileNodes := range files {
		for _, fileNode := range fileNodes {
			p := assembler.IsDependencyIngest{
				Pkg:    toplevel,
				DepPkg: fileNode,
				IsDependency: &model.IsDependencyInputSpec{
					DependencyType: model.DependencyTypeDirect,
					Justification:  justification,
					VersionRange:   *fileNode.Version,
				},
			}
			isDeps = append(isDeps, p)
		}
	}

	return isDeps
}
