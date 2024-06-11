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
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"time"

	"github.com/guacsec/guac/pkg/assembler"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/handler/processor"
)

// TODO: change the DependencyType based on the relationship, currently set to unknown
func GetIsDep(foundNode *model.PkgInputSpec, relatedPackNodes []*model.PkgInputSpec, relatedFileNodes []*model.PkgInputSpec, justification string, dependency model.DependencyType) (*assembler.IsDependencyIngest, error) {
	if len(relatedFileNodes) > 0 {
		for _, rfileNode := range relatedFileNodes {

			// TODO: Check is this always just expected to be one?
			return &assembler.IsDependencyIngest{
				Pkg:             foundNode,
				DepPkg:          rfileNode,
				DepPkgMatchFlag: GetMatchFlagsFromPkgInput(rfileNode),
				IsDependency: &model.IsDependencyInputSpec{
					DependencyType: dependency,
					Justification:  justification,
					VersionRange:   *rfileNode.Version,
				},
			}, nil
		}
	} else if len(relatedPackNodes) > 0 {
		for _, rpackNode := range relatedPackNodes {
			return &assembler.IsDependencyIngest{
				Pkg:             foundNode,
				DepPkg:          rpackNode,
				DepPkgMatchFlag: GetMatchFlagsFromPkgInput(rpackNode),
				IsDependency: &model.IsDependencyInputSpec{
					DependencyType: dependency,
					Justification:  justification,
					VersionRange:   *rpackNode.Version,
				},
			}, nil

		}
	}
	return nil, nil
}

// TODO: change the DependencyType based on the relationship, currently set to unknown
func CreateTopLevelIsDeps(topLevel *model.PkgInputSpec, packages map[string][]*model.PkgInputSpec, files map[string][]*model.PkgInputSpec, justification string) []assembler.IsDependencyIngest {
	isDeps := []assembler.IsDependencyIngest{}
	for _, packNodes := range packages {
		for _, packNode := range packNodes {
			if !reflect.DeepEqual(packNode, topLevel) {
				p := assembler.IsDependencyIngest{
					Pkg:             topLevel,
					DepPkg:          packNode,
					DepPkgMatchFlag: GetMatchFlagsFromPkgInput(packNode),
					IsDependency: &model.IsDependencyInputSpec{
						DependencyType: model.DependencyTypeUnknown,
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
				Pkg:             topLevel,
				DepPkg:          fileNode,
				DepPkgMatchFlag: GetMatchFlagsFromPkgInput(fileNode),
				IsDependency: &model.IsDependencyInputSpec{
					DependencyType: model.DependencyTypeUnknown,
					Justification:  justification,
					VersionRange:   *fileNode.Version,
				},
			}
			isDeps = append(isDeps, p)
		}
	}

	return isDeps
}

func CreateTopLevelHasSBOMFromPkg(topLevelPkg *model.PkgInputSpec, sbomDoc *processor.Document, uri string, timestamp time.Time) assembler.HasSBOMIngest {
	rv := createTopLevelHasSBOM(sbomDoc.Blob, uri, sbomDoc.SourceInformation.Source, timestamp)
	rv.Pkg = topLevelPkg
	return rv
}

func CreateTopLevelHasSBOMFromArtifact(topLevelArt *model.ArtifactInputSpec, sbomDoc *processor.Document, uri string, timestamp time.Time) assembler.HasSBOMIngest {
	rv := createTopLevelHasSBOM(sbomDoc.Blob, uri, sbomDoc.SourceInformation.Source, timestamp)
	rv.Artifact = topLevelArt
	return rv
}

func createTopLevelHasSBOM(blob []byte, uri string, source string, timestamp time.Time) assembler.HasSBOMIngest {
	sha256sum := sha256.Sum256(blob)
	return assembler.HasSBOMIngest{
		HasSBOM: &model.HasSBOMInputSpec{
			Uri:              uri,
			Algorithm:        "sha256",
			Digest:           hex.EncodeToString(sha256sum[:]),
			DownloadLocation: source,
			KnownSince:       timestamp,
		},
	}
}

func GetMatchFlagsFromPkgInput(p *model.PkgInputSpec) model.MatchFlags {
	matchFlags := model.MatchFlags{Pkg: model.PkgMatchTypeAllVersions}
	if p.Version != nil && *p.Version != "" {
		matchFlags = model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion}
	}
	return matchFlags
}
