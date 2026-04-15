//
// Copyright 2026 The GUAC Authors.
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
	"sort"
	"time"

	"github.com/guacsec/guac/pkg/assembler"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/handler/processor"
)

// AddLabels generates HasMetadata predicates from user-provided labels.
// Labels are attached to the package or artifact subjects of any HasSBOM predicates.
func AddLabels(predicates *assembler.IngestPredicates, srcInfo processor.SourceInformation, labels map[string]string) {
	if len(labels) == 0 {
		return
	}

	now := time.Now()

	// Sort keys for deterministic output
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, sbom := range predicates.HasSBOM {
		for _, key := range keys {
			hm := &model.HasMetadataInputSpec{
				Key:           key,
				Value:         labels[key],
				Justification: "Added by guaccollect --label flag",
				Timestamp:     now,
				Collector:     srcInfo.Collector,
				Origin:        srcInfo.Source,
				DocumentRef:   srcInfo.DocumentRef,
			}
			if sbom.Pkg != nil {
				predicates.HasMetadata = append(predicates.HasMetadata, assembler.HasMetadataIngest{
					Pkg:          sbom.Pkg,
					PkgMatchFlag: model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
					HasMetadata:  hm,
				})
			}
			if sbom.Artifact != nil {
				predicates.HasMetadata = append(predicates.HasMetadata, assembler.HasMetadataIngest{
					Artifact:    sbom.Artifact,
					HasMetadata: hm,
				})
			}
		}
	}
}
