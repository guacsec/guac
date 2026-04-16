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
	"testing"

	"github.com/guacsec/guac/pkg/assembler"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/handler/processor"
)

func TestAddLabels_GeneratesHasMetadata(t *testing.T) {
	testPkg := &model.PkgInputSpec{
		Type:      "npm",
		Namespace: strPtr(""),
		Name:      "express",
		Version:   strPtr("4.18.2"),
	}
	testArtifact := &model.ArtifactInputSpec{
		Algorithm: "sha256",
		Digest:    "abc123",
	}

	tests := []struct {
		name            string
		predicates      *assembler.IngestPredicates
		labels          map[string]string
		wantHMCount     int
		wantFirstKey    string
		wantFirstValue  string
		wantHasPkg      bool
		wantHasArtifact bool
	}{
		{
			name: "no labels produces no HasMetadata",
			predicates: &assembler.IngestPredicates{
				HasSBOM: []assembler.HasSBOMIngest{
					{Pkg: testPkg, HasSBOM: &model.HasSBOMInputSpec{}},
				},
			},
			labels:      nil,
			wantHMCount: 0,
		},
		{
			name: "labels on package SBOM",
			predicates: &assembler.IngestPredicates{
				HasSBOM: []assembler.HasSBOMIngest{
					{Pkg: testPkg, HasSBOM: &model.HasSBOMInputSpec{}},
				},
			},
			labels:         map[string]string{"env": "staging", "team": "backend"},
			wantHMCount:    2,
			wantFirstKey:   "env",
			wantFirstValue: "staging",
			wantHasPkg:     true,
		},
		{
			name: "labels on artifact SBOM",
			predicates: &assembler.IngestPredicates{
				HasSBOM: []assembler.HasSBOMIngest{
					{Artifact: testArtifact, HasSBOM: &model.HasSBOMInputSpec{}},
				},
			},
			labels:          map[string]string{"env": "prod"},
			wantHMCount:     1,
			wantFirstKey:    "env",
			wantFirstValue:  "prod",
			wantHasArtifact: true,
		},
		{
			name: "labels on SBOM with both pkg and artifact",
			predicates: &assembler.IngestPredicates{
				HasSBOM: []assembler.HasSBOMIngest{
					{Pkg: testPkg, Artifact: testArtifact, HasSBOM: &model.HasSBOMInputSpec{}},
				},
			},
			labels:      map[string]string{"team": "platform"},
			wantHMCount: 2, // one for pkg, one for artifact
		},
		{
			name: "no HasSBOM means no HasMetadata even with labels",
			predicates: &assembler.IngestPredicates{
				IsDependency: []assembler.IsDependencyIngest{
					{Pkg: testPkg, IsDependency: &model.IsDependencyInputSpec{}},
				},
			},
			labels:      map[string]string{"env": "production"},
			wantHMCount: 0,
		},
		{
			name: "multiple SBOMs multiply labels",
			predicates: &assembler.IngestPredicates{
				HasSBOM: []assembler.HasSBOMIngest{
					{Pkg: testPkg, HasSBOM: &model.HasSBOMInputSpec{}},
					{Artifact: testArtifact, HasSBOM: &model.HasSBOMInputSpec{}},
				},
			},
			labels:      map[string]string{"env": "prod"},
			wantHMCount: 2, // one per SBOM subject
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srcInfo := processor.SourceInformation{
				Collector:   "TestCollector",
				Source:      "test://source",
				DocumentRef: "sha256_test",
			}

			AddLabels(tt.predicates, srcInfo, tt.labels)

			if len(tt.predicates.HasMetadata) != tt.wantHMCount {
				t.Errorf("got %d HasMetadata, want %d", len(tt.predicates.HasMetadata), tt.wantHMCount)
				return
			}

			if tt.wantHMCount == 0 {
				return
			}

			first := tt.predicates.HasMetadata[0]
			if tt.wantFirstKey != "" && first.HasMetadata.Key != tt.wantFirstKey {
				t.Errorf("first HasMetadata key = %q, want %q", first.HasMetadata.Key, tt.wantFirstKey)
			}
			if tt.wantFirstValue != "" && first.HasMetadata.Value != tt.wantFirstValue {
				t.Errorf("first HasMetadata value = %q, want %q", first.HasMetadata.Value, tt.wantFirstValue)
			}
			if tt.wantHasPkg && first.Pkg == nil {
				t.Error("expected first HasMetadata to have Pkg, got nil")
			}
			if tt.wantHasArtifact && first.Artifact == nil {
				t.Error("expected first HasMetadata to have Artifact, got nil")
			}

			// Verify collector metadata is set
			if first.HasMetadata.Collector != "TestCollector" {
				t.Errorf("HasMetadata.Collector = %q, want %q", first.HasMetadata.Collector, "TestCollector")
			}
			if first.HasMetadata.Origin != "test://source" {
				t.Errorf("HasMetadata.Origin = %q, want %q", first.HasMetadata.Origin, "test://source")
			}
		})
	}
}

func strPtr(s string) *string {
	return &s
}
