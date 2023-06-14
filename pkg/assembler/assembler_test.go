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

package assembler

import (
	"context"
	"reflect"
	"testing"

	"github.com/guacsec/guac/pkg/assembler/clients/generated"
)

func TestIngestPredicates_GetPackages(t *testing.T) {
	type fields struct {
		CertifyScorecard []CertifyScorecardIngest
		IsDependency     []IsDependencyIngest
		IsOccurrence     []IsOccurrenceIngest
		HasSlsa          []HasSlsaIngest
		CertifyVuln      []CertifyVulnIngest
		IsVuln           []IsVulnIngest
		HasSourceAt      []HasSourceAtIngest
		CertifyBad       []CertifyBadIngest
		CertifyGood      []CertifyGoodIngest
		HasSBOM          []HasSBOMIngest
		Vex              []VexIngest
		HashEqual        []HashEqualIngest
		PkgEqual         []PkgEqualIngest
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   []*generated.PkgInputSpec
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := IngestPredicates{
				CertifyScorecard: tt.fields.CertifyScorecard,
				IsDependency:     tt.fields.IsDependency,
				IsOccurrence:     tt.fields.IsOccurrence,
				HasSlsa:          tt.fields.HasSlsa,
				CertifyVuln:      tt.fields.CertifyVuln,
				IsVuln:           tt.fields.IsVuln,
				HasSourceAt:      tt.fields.HasSourceAt,
				CertifyBad:       tt.fields.CertifyBad,
				CertifyGood:      tt.fields.CertifyGood,
				HasSBOM:          tt.fields.HasSBOM,
				Vex:              tt.fields.Vex,
				HashEqual:        tt.fields.HashEqual,
				PkgEqual:         tt.fields.PkgEqual,
			}
			if got := i.GetPackages(tt.args.ctx); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("IngestPredicates.GetPackages() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIngestPredicates_GetSources(t *testing.T) {
	type fields struct {
		CertifyScorecard []CertifyScorecardIngest
		IsDependency     []IsDependencyIngest
		IsOccurrence     []IsOccurrenceIngest
		HasSlsa          []HasSlsaIngest
		CertifyVuln      []CertifyVulnIngest
		IsVuln           []IsVulnIngest
		HasSourceAt      []HasSourceAtIngest
		CertifyBad       []CertifyBadIngest
		CertifyGood      []CertifyGoodIngest
		HasSBOM          []HasSBOMIngest
		Vex              []VexIngest
		HashEqual        []HashEqualIngest
		PkgEqual         []PkgEqualIngest
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   []*generated.SourceInputSpec
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := IngestPredicates{
				CertifyScorecard: tt.fields.CertifyScorecard,
				IsDependency:     tt.fields.IsDependency,
				IsOccurrence:     tt.fields.IsOccurrence,
				HasSlsa:          tt.fields.HasSlsa,
				CertifyVuln:      tt.fields.CertifyVuln,
				IsVuln:           tt.fields.IsVuln,
				HasSourceAt:      tt.fields.HasSourceAt,
				CertifyBad:       tt.fields.CertifyBad,
				CertifyGood:      tt.fields.CertifyGood,
				HasSBOM:          tt.fields.HasSBOM,
				Vex:              tt.fields.Vex,
				HashEqual:        tt.fields.HashEqual,
				PkgEqual:         tt.fields.PkgEqual,
			}
			if got := i.GetSources(tt.args.ctx); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("IngestPredicates.GetSources() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIngestPredicates_GetArtifacts(t *testing.T) {
	type fields struct {
		CertifyScorecard []CertifyScorecardIngest
		IsDependency     []IsDependencyIngest
		IsOccurrence     []IsOccurrenceIngest
		HasSlsa          []HasSlsaIngest
		CertifyVuln      []CertifyVulnIngest
		IsVuln           []IsVulnIngest
		HasSourceAt      []HasSourceAtIngest
		CertifyBad       []CertifyBadIngest
		CertifyGood      []CertifyGoodIngest
		HasSBOM          []HasSBOMIngest
		Vex              []VexIngest
		HashEqual        []HashEqualIngest
		PkgEqual         []PkgEqualIngest
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   []*generated.ArtifactInputSpec
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := IngestPredicates{
				CertifyScorecard: tt.fields.CertifyScorecard,
				IsDependency:     tt.fields.IsDependency,
				IsOccurrence:     tt.fields.IsOccurrence,
				HasSlsa:          tt.fields.HasSlsa,
				CertifyVuln:      tt.fields.CertifyVuln,
				IsVuln:           tt.fields.IsVuln,
				HasSourceAt:      tt.fields.HasSourceAt,
				CertifyBad:       tt.fields.CertifyBad,
				CertifyGood:      tt.fields.CertifyGood,
				HasSBOM:          tt.fields.HasSBOM,
				Vex:              tt.fields.Vex,
				HashEqual:        tt.fields.HashEqual,
				PkgEqual:         tt.fields.PkgEqual,
			}
			if got := i.GetArtifacts(tt.args.ctx); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("IngestPredicates.GetArtifacts() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIngestPredicates_GetMaterials(t *testing.T) {
	type fields struct {
		CertifyScorecard []CertifyScorecardIngest
		IsDependency     []IsDependencyIngest
		IsOccurrence     []IsOccurrenceIngest
		HasSlsa          []HasSlsaIngest
		CertifyVuln      []CertifyVulnIngest
		IsVuln           []IsVulnIngest
		HasSourceAt      []HasSourceAtIngest
		CertifyBad       []CertifyBadIngest
		CertifyGood      []CertifyGoodIngest
		HasSBOM          []HasSBOMIngest
		Vex              []VexIngest
		HashEqual        []HashEqualIngest
		PkgEqual         []PkgEqualIngest
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   []generated.ArtifactInputSpec
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := IngestPredicates{
				CertifyScorecard: tt.fields.CertifyScorecard,
				IsDependency:     tt.fields.IsDependency,
				IsOccurrence:     tt.fields.IsOccurrence,
				HasSlsa:          tt.fields.HasSlsa,
				CertifyVuln:      tt.fields.CertifyVuln,
				IsVuln:           tt.fields.IsVuln,
				HasSourceAt:      tt.fields.HasSourceAt,
				CertifyBad:       tt.fields.CertifyBad,
				CertifyGood:      tt.fields.CertifyGood,
				HasSBOM:          tt.fields.HasSBOM,
				Vex:              tt.fields.Vex,
				HashEqual:        tt.fields.HashEqual,
				PkgEqual:         tt.fields.PkgEqual,
			}
			if got := i.GetMaterials(tt.args.ctx); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("IngestPredicates.GetMaterials() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIngestPredicates_GetBuilders(t *testing.T) {
	type fields struct {
		CertifyScorecard []CertifyScorecardIngest
		IsDependency     []IsDependencyIngest
		IsOccurrence     []IsOccurrenceIngest
		HasSlsa          []HasSlsaIngest
		CertifyVuln      []CertifyVulnIngest
		IsVuln           []IsVulnIngest
		HasSourceAt      []HasSourceAtIngest
		CertifyBad       []CertifyBadIngest
		CertifyGood      []CertifyGoodIngest
		HasSBOM          []HasSBOMIngest
		Vex              []VexIngest
		HashEqual        []HashEqualIngest
		PkgEqual         []PkgEqualIngest
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   []*generated.BuilderInputSpec
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := IngestPredicates{
				CertifyScorecard: tt.fields.CertifyScorecard,
				IsDependency:     tt.fields.IsDependency,
				IsOccurrence:     tt.fields.IsOccurrence,
				HasSlsa:          tt.fields.HasSlsa,
				CertifyVuln:      tt.fields.CertifyVuln,
				IsVuln:           tt.fields.IsVuln,
				HasSourceAt:      tt.fields.HasSourceAt,
				CertifyBad:       tt.fields.CertifyBad,
				CertifyGood:      tt.fields.CertifyGood,
				HasSBOM:          tt.fields.HasSBOM,
				Vex:              tt.fields.Vex,
				HashEqual:        tt.fields.HashEqual,
				PkgEqual:         tt.fields.PkgEqual,
			}
			if got := i.GetBuilders(tt.args.ctx); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("IngestPredicates.GetBuilders() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIngestPredicates_GetCVEs(t *testing.T) {
	type fields struct {
		CertifyScorecard []CertifyScorecardIngest
		IsDependency     []IsDependencyIngest
		IsOccurrence     []IsOccurrenceIngest
		HasSlsa          []HasSlsaIngest
		CertifyVuln      []CertifyVulnIngest
		IsVuln           []IsVulnIngest
		HasSourceAt      []HasSourceAtIngest
		CertifyBad       []CertifyBadIngest
		CertifyGood      []CertifyGoodIngest
		HasSBOM          []HasSBOMIngest
		Vex              []VexIngest
		HashEqual        []HashEqualIngest
		PkgEqual         []PkgEqualIngest
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   []*generated.CVEInputSpec
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := IngestPredicates{
				CertifyScorecard: tt.fields.CertifyScorecard,
				IsDependency:     tt.fields.IsDependency,
				IsOccurrence:     tt.fields.IsOccurrence,
				HasSlsa:          tt.fields.HasSlsa,
				CertifyVuln:      tt.fields.CertifyVuln,
				IsVuln:           tt.fields.IsVuln,
				HasSourceAt:      tt.fields.HasSourceAt,
				CertifyBad:       tt.fields.CertifyBad,
				CertifyGood:      tt.fields.CertifyGood,
				HasSBOM:          tt.fields.HasSBOM,
				Vex:              tt.fields.Vex,
				HashEqual:        tt.fields.HashEqual,
				PkgEqual:         tt.fields.PkgEqual,
			}
			if got := i.GetCVEs(tt.args.ctx); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("IngestPredicates.GetCVEs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIngestPredicates_GetOSVs(t *testing.T) {
	type fields struct {
		CertifyScorecard []CertifyScorecardIngest
		IsDependency     []IsDependencyIngest
		IsOccurrence     []IsOccurrenceIngest
		HasSlsa          []HasSlsaIngest
		CertifyVuln      []CertifyVulnIngest
		IsVuln           []IsVulnIngest
		HasSourceAt      []HasSourceAtIngest
		CertifyBad       []CertifyBadIngest
		CertifyGood      []CertifyGoodIngest
		HasSBOM          []HasSBOMIngest
		Vex              []VexIngest
		HashEqual        []HashEqualIngest
		PkgEqual         []PkgEqualIngest
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   []*generated.OSVInputSpec
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := IngestPredicates{
				CertifyScorecard: tt.fields.CertifyScorecard,
				IsDependency:     tt.fields.IsDependency,
				IsOccurrence:     tt.fields.IsOccurrence,
				HasSlsa:          tt.fields.HasSlsa,
				CertifyVuln:      tt.fields.CertifyVuln,
				IsVuln:           tt.fields.IsVuln,
				HasSourceAt:      tt.fields.HasSourceAt,
				CertifyBad:       tt.fields.CertifyBad,
				CertifyGood:      tt.fields.CertifyGood,
				HasSBOM:          tt.fields.HasSBOM,
				Vex:              tt.fields.Vex,
				HashEqual:        tt.fields.HashEqual,
				PkgEqual:         tt.fields.PkgEqual,
			}
			if got := i.GetOSVs(tt.args.ctx); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("IngestPredicates.GetOSVs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIngestPredicates_GetGHSAs(t *testing.T) {
	type fields struct {
		CertifyScorecard []CertifyScorecardIngest
		IsDependency     []IsDependencyIngest
		IsOccurrence     []IsOccurrenceIngest
		HasSlsa          []HasSlsaIngest
		CertifyVuln      []CertifyVulnIngest
		IsVuln           []IsVulnIngest
		HasSourceAt      []HasSourceAtIngest
		CertifyBad       []CertifyBadIngest
		CertifyGood      []CertifyGoodIngest
		HasSBOM          []HasSBOMIngest
		Vex              []VexIngest
		HashEqual        []HashEqualIngest
		PkgEqual         []PkgEqualIngest
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   []*generated.GHSAInputSpec
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := IngestPredicates{
				CertifyScorecard: tt.fields.CertifyScorecard,
				IsDependency:     tt.fields.IsDependency,
				IsOccurrence:     tt.fields.IsOccurrence,
				HasSlsa:          tt.fields.HasSlsa,
				CertifyVuln:      tt.fields.CertifyVuln,
				IsVuln:           tt.fields.IsVuln,
				HasSourceAt:      tt.fields.HasSourceAt,
				CertifyBad:       tt.fields.CertifyBad,
				CertifyGood:      tt.fields.CertifyGood,
				HasSBOM:          tt.fields.HasSBOM,
				Vex:              tt.fields.Vex,
				HashEqual:        tt.fields.HashEqual,
				PkgEqual:         tt.fields.PkgEqual,
			}
			if got := i.GetGHSAs(tt.args.ctx); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("IngestPredicates.GetGHSAs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_concatenateSourceInput(t *testing.T) {
	type args struct {
		source *generated.SourceInputSpec
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := concatenateSourceInput(tt.args.source); got != tt.want {
				t.Errorf("concatenateSourceInput() = %v, want %v", got, tt.want)
			}
		})
	}
}
