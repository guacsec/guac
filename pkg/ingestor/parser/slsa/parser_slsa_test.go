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

package slsa

import (
	"context"
	"reflect"
	"testing"
	"time"

	scommon "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	slsa01 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.1"

	"github.com/in-toto/in-toto-golang/in_toto"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

func Test_slsaParser(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	tests := []struct {
		name           string
		doc            *processor.Document
		wantPredicates *assembler.IngestPredicates
		wantErr        bool
	}{
		{
			name:           "testing v0.2",
			doc:            &testdata.Ite6SLSADoc,
			wantPredicates: &testdata.SlsaPreds,
			wantErr:        false,
		},
		{
			name:           "testing v1",
			doc:            &testdata.Ite6SLSA1Doc,
			wantPredicates: &testdata.SlsaPreds1,
			wantErr:        false,
		},
		{
			name:           "testing v1-2",
			doc:            &testdata.Ite6SLSA1Doc_2,
			wantPredicates: &testdata.SlsaPreds1_2,
			wantErr:        false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSLSAParser()
			err := s.Parse(ctx, tt.doc)
			if (err != nil) != tt.wantErr {
				t.Errorf("slsa.Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			preds := s.GetPredicates(ctx)
			//fmt.Println(preds.HasSlsa[0].HasSlsa.SlsaPredicate)
			if d := cmp.Diff(tt.wantPredicates, preds, testdata.IngestPredicatesCmpOpts...); len(d) != 0 {
				t.Errorf("slsa.GetPredicate mismatch values (+got, -expected): %s", d)
			}
		})
	}
}

func Test_fillSLSA01(t *testing.T) {
	startTime := time.Now()
	endTime := time.Now()
	type args struct {
		inp  *model.SLSAInputSpec
		stmt *in_toto.ProvenanceStatementSLSA01
	}
	tests := []struct {
		name string
		args args
		err  error
	}{
		{
			name: "default",
			args: args{
				inp: &model.SLSAInputSpec{},
				stmt: &in_toto.ProvenanceStatementSLSA01{
					Predicate: slsa01.ProvenancePredicate{
						Metadata: &slsa01.ProvenanceMetadata{
							BuildStartedOn:  &startTime,
							BuildFinishedOn: &endTime,
						},
						Recipe: slsa01.ProvenanceRecipe{
							Type: "test",
						},
					},
				},
			},
		},
		{
			name: "stmt predicate metadata is nil",
			args: args{
				inp:  &model.SLSAInputSpec{},
				stmt: &in_toto.ProvenanceStatementSLSA01{},
			},
			err: ErrMetadataNil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := fillSLSA01(test.args.inp, &test.args.stmt.Predicate)
			if err != test.err {
				t.Fatalf("fillSLSA01() error = %v, expected error %v", err, test.err)
			}
			if err != nil {
				// if the error is equal to the expected error, we can return
				// we know that the error is equal to the expected error because we checked if it wasn't equal above
				// if err == nil then we know that the function didn't throw an error, and we have to check the values
				return
			}

			if test.args.inp.BuildType != test.args.stmt.Predicate.Recipe.Type {
				t.Errorf("fillSLSA01() inp.BuildType not equal to stmt.Predicate.Recipe.Type")
			}
			if test.args.inp.StartedOn != test.args.stmt.Predicate.Metadata.BuildStartedOn {
				t.Errorf("fillSLSA01() inp.BuildStartedOn not equal to stmt.Predicate.Metadata.BuildStartedOn")
			}
			if test.args.inp.FinishedOn != test.args.stmt.Predicate.Metadata.BuildFinishedOn {
				t.Errorf("fillSLSA01() inp.BuildFinishedOn not equal to stmt.Predicate.Metadata.BuildFinishedOn")
			}
		})
	}
}

func Test_getSlsaEntity(t *testing.T) {
	namespace := "sigstore"
	genericNamespace := "generic"
	version := "4.2.0"
	emptyString := ""
	tests := []struct {
		testname string
		uri      string
		name     string
		digest   scommon.DigestSet
		expected *slsaEntity
		wantErr  bool
	} {
		{
			testname: "with uri and digest",
			uri: "pkg:npm/sigstore/sigstore-js@4.2.0",
			digest: scommon.DigestSet{
				"sha1": "428601801d1f5d105351a403f58c38269de93f680",
			},
			expected: &slsaEntity{
				artifacts: []*model.ArtifactInputSpec{
					{
						Algorithm: "sha1",
						Digest: "428601801d1f5d105351a403f58c38269de93f680",
					},
				},
				pkg: &model.PkgInputSpec{
					Type: "npm",
					Namespace: &namespace,
					Name: "sigstore-js",
					Version: &version,
					Subpath: &emptyString,
				},
				occurence:  &model.IsOccurrenceInputSpec{
					Justification: "from SLSA definition of checksums for subject/materials",
				},
			},
			wantErr: false,
		},
		{
			testname: "with name and digest",
			name: "sigstore",
			digest: scommon.DigestSet{
				"sha1": "428601801d1f5d105351a403f58c38269de93f680",
			},
			expected: &slsaEntity{
				artifacts: []*model.ArtifactInputSpec{
					{
						Algorithm: "sha1",
						Digest: "428601801d1f5d105351a403f58c38269de93f680",
					},
				},
				pkg: &model.PkgInputSpec{
					Type: "guac",
					Namespace: &genericNamespace,
					Name: "sigstore",
					Subpath: &emptyString,
					Version: &emptyString,
				},
				occurence:  &model.IsOccurrenceInputSpec{
					Justification: "from SLSA definition of checksums for subject/materials",
				},
			},
			wantErr: false,
		},
		{
			testname: "without name and uri",
			digest: scommon.DigestSet{
				"sha1": "428601801d1f5d105351a403f58c38269de93f680",
			},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.testname, func(t *testing.T) {
			s, err := getSlsaEntity(test.name, test.uri, test.digest)
			if (err != nil) != test.wantErr {
				t.Errorf("slsa.Parse() error is not as expected. Expected: %v, Got: %v", err, test.wantErr)
				return
			}
			if err != nil {
				return
			}
			if !reflect.DeepEqual(s.pkg, test.expected.pkg) {
				t.Errorf("getSlsaEntity() package is not as expected. Expected: %v, Got: %v", *s.pkg.Version, *test.expected.pkg.Version)
			}
			if !reflect.DeepEqual(s.source, test.expected.source) {
				t.Errorf("getSlsaEntity() source is not as expected. Expected: %v, Got: %v", s.source, test.expected.source)
			}
			if !reflect.DeepEqual(s.occurence, test.expected.occurence) {
				t.Errorf("getSlsaEntity() occurence is not as expected. Expected: %v, Got: %v", s.occurence, test.expected.occurence)
			}
			if !reflect.DeepEqual(s.artifacts, test.expected.artifacts) {
				t.Errorf("getSlsaEntity() artifact is not as expected. Expected: %v, Got: %v", s.artifacts, test.expected.artifacts)
			}
		})
	}
}