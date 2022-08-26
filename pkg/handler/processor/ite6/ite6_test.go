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
	"encoding/json"
	"reflect"
	"testing"

	"github.com/guacsec/guac/pkg/handler/processor"
	v02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
)

var (
	badProvenance = `{
		"_type": ["https://in-toto.io/Statement/v0.1"],
		"subject": [{"name": "_", "digest": {"sha256": "5678..."}}],
	}`
	unknownProvenance = `{
		"_type": "https://in-toto.io/Statement/v0.1",
		"subject": [{"name": "_", "digest": {"sha256": "5678..."}}],
		"predicateType": "https://hello-world/provenance/v0.2",
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
	// Taken from: https://slsa.dev/provenance/v0.1#example
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

	predicate = v02.ProvenancePredicate{
		Builder: v02.ProvenanceBuilder{
			ID: "https://github.com/Attestations/GitHubHostedActions@v1",
		},
		BuildType: "https://github.com/Attestations/GitHubActionsWorkflow@v1",
		Invocation: v02.ProvenanceInvocation{
			ConfigSource: v02.ConfigSource{
				URI: "git+https://github.com/curl/curl-docker@master",
				Digest: v02.DigestSet{
					"sha1": "d6525c840a62b398424a78d792f457477135d0cf",
				},
				EntryPoint: "build.yaml:maketgz",
			},
		},
		Metadata: &v02.ProvenanceMetadata{
			Completeness: v02.ProvenanceComplete{
				Environment: true,
			},
		},
		Materials: []v02.ProvenanceMaterial{
			{
				URI: "git+https://github.com/curl/curl-docker@master",
				Digest: v02.DigestSet{
					"sha1": "d6525c840a62b398424a78d792f457477135d0cf",
				},
			},
			{
				URI: "github_hosted_vm:ubuntu-18.04:20210123.1",
			},
		},
	}
)

func TestITE6Processor_ValidateSchema(t *testing.T) {
	tests := []struct {
		name    string
		args    *processor.Document
		wantErr bool
	}{
		{
			name: "ITE6 Doc with unknown payload",
			args: &processor.Document{
				Blob:   []byte(badProvenance),
				Type:   processor.DocumentITE6,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: "TestCollector",
					Source:    "TestSource",
				},
			},
			wantErr: true,
		},
		{
			name: "ITE6 Doc with valid payload",
			args: &processor.Document{
				Blob:   []byte(ite6SLSA),
				Type:   processor.DocumentITE6,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: "TestCollector",
					Source:    "TestSource",
				},
			},
			wantErr: false,
		},
	}
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
	predicatePayload, _ := json.Marshal(predicate)
	tests := []struct {
		name    string
		args    *processor.Document
		want    []*processor.Document
		wantErr bool
	}{
		{
			name: "ITE6 Doc with unknown payload",
			args: &processor.Document{
				Blob:   []byte(unknownProvenance),
				Type:   processor.DocumentITE6,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: "TestCollector",
					Source:    "TestSource",
				},
			},
			want: []*processor.Document{{
				Blob:   predicatePayload,
				Type:   processor.DocumentUnknown,
				Format: processor.FormatUnknown,
				SourceInformation: processor.SourceInformation{
					Collector: "TestCollector",
					Source:    "TestSource",
				},
			}},
			wantErr: false,
		},
		{
			name: "ITE6 Doc with valid payload",
			args: &processor.Document{
				Blob:   []byte(ite6SLSA),
				Type:   processor.DocumentITE6,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: "TestCollector",
					Source:    "TestSource",
				},
			},
			want: []*processor.Document{{
				Blob:   predicatePayload,
				Type:   processor.DocumentSLSA,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: "TestCollector",
					Source:    "TestSource",
				},
			}},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &ITE6Processor{}
			got, err := e.Unpack(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("ITE6Processor.Unpack() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			parsedGot := parseV02(got[0].Blob)
			parsedWant := parseV02(tt.want[0].Blob)
			if !reflect.DeepEqual(parsedGot, parsedWant) {
				t.Errorf("ITE6Processor.Unpack() blobs = %v, want %v", parsedGot, parsedWant)
			}
			if !reflect.DeepEqual(got[0].Type, tt.want[0].Type) {
				t.Errorf("ITE6Processor.Unpack() Type = %v, want %v", got[0].Type, tt.want[0].Type)
			}
			if !reflect.DeepEqual(got[0].Format, tt.want[0].Format) {
				t.Errorf("ITE6Processor.Unpack() Format = %v, want %v", got[0].Format, tt.want[0].Format)
			}
			if !reflect.DeepEqual(got[0].SourceInformation, tt.want[0].SourceInformation) {
				t.Errorf("ITE6Processor.Unpack() SourceInformation = %v, want %v", got[0].SourceInformation, tt.want[0].SourceInformation)
			}
		})
	}
}

func parseV02(p []byte) *v02.ProvenancePredicate {
	ps := v02.ProvenancePredicate{}
	if err := json.Unmarshal(p, &ps); err != nil {
		return nil
	}
	return &ps
}
