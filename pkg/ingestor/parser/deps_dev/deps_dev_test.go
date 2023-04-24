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

package deps_dev

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/guacsec/guac/pkg/logging"
)

func TestNewDepsDevParser(t *testing.T) {
	tests := []struct {
		name string
		want common.DocumentParser
	}{{
		name: "new deps.dev parser",
		want: &depsDevParser{},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewDepsDevParser(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewDepsDevParser() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_depsDevParser_Parse(t *testing.T) {
	tm, _ := time.Parse(time.RFC3339, "2022-11-21T17:45:50.52Z")
	ctx := logging.WithLogger(context.Background())

	tests := []struct {
		name           string
		doc            *processor.Document
		wantPredicates *assembler.IngestPredicates
		wantErr        bool
	}{{
		name: "package foreign-types",
		doc: &processor.Document{
			Blob:              []byte(testdata.CollectedForeignTypes),
			Type:              processor.DocumentDepsDev,
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		},
		wantPredicates: &assembler.IngestPredicates{
			CertifyScorecard: []assembler.CertifyScorecardIngest{
				{
					Source: &model.SourceInputSpec{
						Type:      "git",
						Namespace: "github.com/sfackler",
						Name:      "foreign-types",
					},
					Scorecard: &model.ScorecardInputSpec{
						Checks: []model.ScorecardCheckInputSpec{
							{Check: "Maintained", Score: 5},
							{Check: "CII-Best-Practices", Score: 0},
							{Check: "License", Score: 10},
							{Check: "Signed-Releases", Score: -1},
							{Check: "Dangerous-Workflow", Score: 10},
							{Check: "Pinned-Dependencies", Score: 7},
							{Check: "Binary-Artifacts", Score: 10},
							{Check: "Token-Permissions", Score: 0},
							{Check: "Packaging", Score: -1},
							{Check: "Vulnerabilities", Score: 10},
							{Check: "Fuzzing", Score: 0},
							{Check: "Branch-Protection", Score: 0},
							{Check: "Security-Policy", Score: 0},
						},
						AggregateScore:   4.599999904632568,
						TimeScanned:      tm.UTC(),
						ScorecardVersion: "v4.10.5-46-gb16c74b",
						ScorecardCommit:  "b16c74bd16a7aba296227115ca0110b9e0a87742",
						Origin:           "",
						Collector:        "",
					},
				}, {
					Source: &model.SourceInputSpec{
						Type:      "git",
						Namespace: "github.com/sfackler",
						Name:      "foreign-types",
					},
					Scorecard: &model.ScorecardInputSpec{
						Checks: []model.ScorecardCheckInputSpec{
							{Check: "Maintained", Score: 5},
							{Check: "CII-Best-Practices", Score: 0},
							{Check: "License", Score: 10},
							{Check: "Signed-Releases", Score: -1},
							{Check: "Dangerous-Workflow", Score: 10},
							{Check: "Pinned-Dependencies", Score: 7},
							{Check: "Binary-Artifacts", Score: 10},
							{Check: "Token-Permissions", Score: 0},
							{Check: "Packaging", Score: -1},
							{Check: "Vulnerabilities", Score: 10},
							{Check: "Fuzzing", Score: 0},
							{Check: "Branch-Protection", Score: 0},
							{Check: "Security-Policy", Score: 0},
						},
						AggregateScore:   4.599999904632568,
						TimeScanned:      tm.UTC(),
						ScorecardVersion: "v4.10.5-46-gb16c74b",
						ScorecardCommit:  "b16c74bd16a7aba296227115ca0110b9e0a87742",
						Origin:           "",
						Collector:        "",
					},
				},
			},
			IsDependency: []assembler.IsDependencyIngest{
				{
					Pkg: &model.PkgInputSpec{
						Type:      "cargo",
						Namespace: ptrfrom.String(""),
						Name:      "foreign-types",
						Version:   ptrfrom.String("0.3.2"),
						Subpath:   ptrfrom.String(""),
					},
					DepPkg: &model.PkgInputSpec{
						Type:      "cargo",
						Namespace: ptrfrom.String(""),
						Name:      "foreign-types-shared",
						Version:   ptrfrom.String("0.1.1"),
						Subpath:   ptrfrom.String(""),
					},
					IsDependency: &model.IsDependencyInputSpec{
						VersionRange:  "0.1.1",
						Justification: "dependency data collected via deps.dev",
						Origin:        "",
						Collector:     "",
					},
				},
			},
			HasSourceAt: []assembler.HasSourceAtIngest{
				{
					Pkg: &model.PkgInputSpec{
						Type:      "cargo",
						Namespace: ptrfrom.String(""),
						Name:      "foreign-types",
						Version:   ptrfrom.String("0.3.2"),
						Subpath:   ptrfrom.String(""),
					},
					PkgMatchFlag: model.MatchFlags{
						Pkg: model.PkgMatchTypeAllVersions,
					},
					Src: &model.SourceInputSpec{
						Type:      "git",
						Namespace: "github.com/sfackler",
						Name:      "foreign-types",
					},
					HasSourceAt: &model.HasSourceAtInputSpec{
						KnownSince:    tm.UTC(),
						Justification: "collected via deps.dev",
						Origin:        "",
						Collector:     "",
					},
				}, {
					Pkg: &model.PkgInputSpec{
						Type:      "cargo",
						Namespace: ptrfrom.String(""),
						Name:      "foreign-types-shared",
						Version:   ptrfrom.String("0.1.1"),
						Subpath:   ptrfrom.String(""),
					},
					PkgMatchFlag: model.MatchFlags{
						Pkg: model.PkgMatchTypeAllVersions,
					},
					Src: &model.SourceInputSpec{
						Type:      "git",
						Namespace: "github.com/sfackler",
						Name:      "foreign-types",
					},
					HasSourceAt: &model.HasSourceAtInputSpec{
						KnownSince:    tm.UTC(),
						Justification: "collected via deps.dev",
						Origin:        "",
						Collector:     "",
					},
				},
			},
		},
		wantErr: false,
	}, {
		name: "package yargs-parser",
		doc: &processor.Document{
			Blob:              []byte(testdata.CollectedYargsParser),
			Type:              processor.DocumentDepsDev,
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		},
		wantPredicates: &assembler.IngestPredicates{
			IsDependency: []assembler.IsDependencyIngest{
				{
					Pkg: &model.PkgInputSpec{
						Type:      "npm",
						Namespace: ptrfrom.String(""),
						Name:      "yargs-parser",
						Version:   ptrfrom.String("4.2.1"),
						Subpath:   ptrfrom.String(""),
					},
					DepPkg: &model.PkgInputSpec{
						Type:      "npm",
						Namespace: ptrfrom.String(""),
						Name:      "camelcase",
						Version:   ptrfrom.String("3.0.0"),
						Subpath:   ptrfrom.String(""),
					},
					IsDependency: &model.IsDependencyInputSpec{
						VersionRange:  "3.0.0",
						Justification: "dependency data collected via deps.dev",
						Origin:        "",
						Collector:     "",
					},
				},
			},
			HasSourceAt: []assembler.HasSourceAtIngest{
				{
					Pkg: &model.PkgInputSpec{
						Type:      "npm",
						Namespace: ptrfrom.String(""),
						Name:      "yargs-parser",
						Version:   ptrfrom.String("4.2.1"),
						Subpath:   ptrfrom.String(""),
					},
					PkgMatchFlag: model.MatchFlags{
						Pkg: model.PkgMatchTypeAllVersions,
					},
					Src: &model.SourceInputSpec{
						Type:      "git",
						Namespace: "github.com/yargs",
						Name:      "yargs-parser.git",
					},
					HasSourceAt: &model.HasSourceAtInputSpec{
						KnownSince:    tm.UTC(),
						Justification: "collected via deps.dev",
						Origin:        "",
						Collector:     "",
					},
				},
				{
					Pkg: &model.PkgInputSpec{
						Type:      "npm",
						Namespace: ptrfrom.String(""),
						Name:      "camelcase",
						Version:   ptrfrom.String("3.0.0"),
						Subpath:   ptrfrom.String(""),
					},
					PkgMatchFlag: model.MatchFlags{
						Pkg: model.PkgMatchTypeAllVersions,
					},
					Src: &model.SourceInputSpec{
						Type:      "git",
						Namespace: "github.com/sindresorhus",
						Name:      "camelcase.git",
					},
					HasSourceAt: &model.HasSourceAtInputSpec{
						KnownSince:    tm.UTC(),
						Justification: "collected via deps.dev",
						Origin:        "",
						Collector:     "",
					},
				},
			},
		},
		wantErr: false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewDepsDevParser()
			if err := d.Parse(ctx, tt.doc); (err != nil) != tt.wantErr {
				t.Errorf("deps.dev.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
			preds := d.GetPredicates(ctx)
			if d := cmp.Diff(tt.wantPredicates, preds, testdata.IngestPredicatesCmpOpts...); len(d) != 0 {
				t.Errorf("deps.dev.GetPredicate mismatch values (+got, -expected): %s", d)
			}
		})
	}
}

// TODO (pxp928): Unit test will also need to be fixed after issue https://github.com/guacsec/guac/issues/769 is resolved

// func Test_depsDevParser_GetIdentifiers(t *testing.T) {
// 	ctx := logging.WithLogger(context.Background())

// 	tests := []struct {
// 		name            string
// 		doc             *processor.Document
// 		wantIdentifiers *common.IdentifierStrings
// 		wantErr         bool
// 	}{{
// 		name: "package foreign-types",
// 		doc: &processor.Document{
// 			Blob:              []byte(testdata.CollectedForeignTypes),
// 			Type:              processor.DocumentDepsDev,
// 			Format:            processor.FormatJSON,
// 			SourceInformation: processor.SourceInformation{},
// 		},
// 		wantIdentifiers: &common.IdentifierStrings{
// 			PurlStrings: []string{"pkg:cargo/foreign-types-shared@0.1.1"}},
// 		wantErr: false,
// 	}, {
// 		name: "package yargs-parser",
// 		doc: &processor.Document{
// 			Blob:              []byte(testdata.CollectedYargsParser),
// 			Type:              processor.DocumentDepsDev,
// 			Format:            processor.FormatJSON,
// 			SourceInformation: processor.SourceInformation{},
// 		},
// 		wantIdentifiers: &common.IdentifierStrings{
// 			PurlStrings: []string{"pkg:npm/camelcase@3.0.0"}},
// 		wantErr: false,
// 	}}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			d := NewDepsDevParser()
// 			if err := d.Parse(ctx, tt.doc); (err != nil) != tt.wantErr {
// 				t.Errorf("deps.dev.Parse() error = %v, wantErr %v", err, tt.wantErr)
// 			}
// 			identifiers, err := d.GetIdentifiers(ctx)
// 			if (err != nil) != tt.wantErr {
// 				t.Errorf("deps.dev.GetIdentifiers() error = %v, wantErr %v", err, tt.wantErr)
// 			}
// 			if d := cmp.Diff(tt.wantIdentifiers, identifiers); len(d) != 0 {
// 				t.Errorf("deps.dev.GetPredicate mismatch values (+got, -expected): %s", d)
// 			}
// 		})
// 	}
// }
