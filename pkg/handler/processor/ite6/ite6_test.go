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

package ite6

import (
	"reflect"
	"testing"

	testdata "github.com/guacsec/guac/internal/testing/processor"
	"github.com/guacsec/guac/pkg/handler/processor"
)

var (
	badProvenance = `{
		"_type": ["https://in-toto.io/Statement/v0.1"],
		"subject": [{"name": "_", "digest": {"sha256": "5678..."}}],
	}`
	ite6SLSA = `{
		"_type": "https://in-toto.io/Statement/v0.1",
		"subject": [{"name": "_", "digest": {"sha256": "5678..."}}],
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate":
			{
				"builder": { "id": "https://github.com/Attestations/GitHubHostedActions@v1" },
				"buildType": "https://github.com/Attestations/GitHubActionsWorkflow@v1",
				"invocation": {
				  "configSource": {
					"uri": "git+https://github.com/curl/curl-docker@master",
					"digest": { "sha1": "d6525c840a62b398424a78d792f457477135d0cf" },   
					"entryPoint": "build.yaml:maketgz"
				  }
				},
				"metadata": {
				  "completeness": {
					  "environment": true
				  }
				},
				"materials": [
				  {
					"uri": "git+https://github.com/curl/curl-docker@master",
					"digest": { "sha1": "d6525c840a62b398424a78d792f457477135d0cf" }
				  }, {
					"uri": "github_hosted_vm:ubuntu-18.04:20210123.1"
				  }
				]
			}
	}`
)

func TestITE6Processor_ValidateSchema(t *testing.T) {
	tests := []struct {
		name    string
		args    *processor.Document
		wantErr bool
	}{{
		name: "ITE6 Doc with unknown payload",
		args: &processor.Document{
			Blob:   []byte(badProvenance),
			Type:   processor.DocumentITE6Unknown,
			Format: processor.FormatJSON,
			SourceInformation: processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		},
		wantErr: true,
	}, {
		name: "ITE6 Doc with valid payload",
		args: &processor.Document{
			Blob:   []byte(ite6SLSA),
			Type:   processor.DocumentITE6SLSA,
			Format: processor.FormatJSON,
			SourceInformation: processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		},
		wantErr: false,
	}, {
		name: "ITE6 CREV with valid payload",
		args: &processor.Document{
			Blob:   []byte(testdata.ITE6CREVExample),
			Type:   processor.DocumentITE6CREV,
			Format: processor.FormatJSON,
			SourceInformation: processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		},
		wantErr: false,
	}, {
		name: "ITE6 Review with valid payload",
		args: &processor.Document{
			Blob:   []byte(testdata.ITE6ReviewExample),
			Type:   processor.DocumentITE6REVIEW,
			Format: processor.FormatJSON,
			SourceInformation: processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		},
		wantErr: false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &ITE6Processor{}
			if err := e.ValidateSchema(tt.args); (err != nil) != tt.wantErr {
				t.Errorf("ITE6Processor.ValidateSchema() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestITE6Processor_Unpack(t *testing.T) {
	tests := []struct {
		name    string
		args    *processor.Document
		want    []*processor.Document
		wantErr bool
	}{{
		name: "ITE6 Doc with valid payload",
		args: &processor.Document{
			Blob:   []byte(ite6SLSA),
			Type:   processor.DocumentITE6SLSA,
			Format: processor.FormatJSON,
			SourceInformation: processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		},
		wantErr: false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &ITE6Processor{}
			got, err := e.Unpack(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("ITE6Processor.ValidateSchema() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DSSEProcessor.Unpack() = %v, expected %v", got, tt.want)
			}
		})
	}
}
