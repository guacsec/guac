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

package verifier

import (
	"context"
	"encoding/base64"
	"reflect"
	"strings"
	"sync"
	"testing"

	jsoniter "github.com/json-iterator/go"

	"github.com/guacsec/guac/internal/testing/keyutil"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/key"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

var (
	json = jsoniter.ConfigCompatibleWithStandardLibrary
	once sync.Once
	// Taken from: https://slsa.dev/provenance/v0.1#example
	ite6SLSA = `
	{
		"_type": "https://in-toto.io/Statement/v0.1",
		"subject": [{"name": "helloworld", "digest": {"sha256": "5678..."}}],
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
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
			  "buildStartedOn": "2020-08-19T08:38:00Z",
			  "completeness": {
				  "environment": true
			  }
			},
			"materials": [
			  {
				"uri": "git+https://github.com/curl/curl-docker@master",
				"digest": { "sha1": "d6525c840a62b398424a78d792f457477135d0cf" }
			  }, {
				"uri": "github_hosted_vm:ubuntu-18.04:20210123.1",
				"digest": { "sha1": "d6525c840a62b398424a78d792f457477135d0cf" }
			  }
			]
		}
	}`
	b64ITE6SLSA    = base64.StdEncoding.EncodeToString([]byte(ite6SLSA))
	ite6Payload, _ = json.Marshal(dsse.Envelope{
		PayloadType: "https://in-toto.io/Statement/v0.1",
		Payload:     b64ITE6SLSA,
		Signatures: []dsse.Signature{{
			KeyID: "id1",
			Sig:   "test",
		}},
	})
	ite6DSSEDoc = processor.Document{
		Blob:   ite6Payload,
		Type:   processor.DocumentDSSE,
		Format: processor.FormatJSON,
		SourceInformation: processor.SourceInformation{
			Collector: "TestCollector",
			Source:    "TestSource",
		},
	}
	unknownDoc = processor.Document{
		Blob:   []byte("fake payload"),
		Type:   processor.DocumentUnknown,
		Format: processor.FormatJSON,
		SourceInformation: processor.SourceInformation{
			Collector: "TestCollector",
			Source:    "TestSource",
		},
	}
	ecdsaPubKey, _, _ = keyutil.GetECDSAPubKey()
)

type mockSigstoreVerifier struct{}

func newMockSigstoreVerifier() *mockSigstoreVerifier {
	return &mockSigstoreVerifier{}
}

func (m *mockSigstoreVerifier) Verify(ctx context.Context, payloadBytes []byte) ([]Identity, error) {
	keyHash, err := dsse.SHA256KeyID(ecdsaPubKey)
	if err != nil {
		return nil, err
	}
	return []Identity{
		{
			ID: "test",
			Key: key.Key{
				Hash:   keyHash,
				Type:   "ecdsa",
				Val:    ecdsaPubKey,
				Scheme: "ecdsa",
			},
			Verified: true,
		},
	}, nil
}

func (m *mockSigstoreVerifier) Type() VerifierType {
	return "sigstore"
}

func TestVerifyIdentity(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	var err error
	once.Do(func() {
		err = RegisterVerifier(newMockSigstoreVerifier(), "sigstore")
	})
	if err != nil {
		t.Errorf("RegisterVerifier() failed with error: %v", err)
	}
	err = RegisterVerifier(newMockSigstoreVerifier(), "sigstore")
	if (err != nil) != true {
		t.Errorf("RegisterVerifier() error = %v, wantErr %v", err, true)
	}
	if !strings.Contains(err.Error(), "the verification provider is being overwritten: sigstore") {
		t.Errorf("RegisterVerifier() failed on wrong error %v", err)
	}

	keyHash, err := dsse.SHA256KeyID(ecdsaPubKey)
	if err != nil {
		t.Fatal("failed to get key hash for test")
	}
	tests := []struct {
		name    string
		doc     *processor.Document
		want    []Identity
		wantErr bool
	}{{
		name: "verify",
		doc:  &ite6DSSEDoc,
		want: []Identity{
			{
				ID: "test",
				Key: key.Key{
					Hash:   keyHash,
					Type:   "ecdsa",
					Val:    ecdsaPubKey,
					Scheme: "ecdsa",
				},
				Verified: true,
			},
		},
		wantErr: false,
	}, {
		name:    "not found",
		doc:     &unknownDoc,
		wantErr: true,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := VerifyIdentity(ctx, tt.doc)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyIdentity() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("VerifyIdentity() = %v, want %v", got, tt.want)
				}
			} else {
				if !strings.Contains(err.Error(), "failed verification for document type: UNKNOWN") {
					t.Errorf("VerifyIdentity() failed on wrong error %v", err)
				}
			}
		})
	}
}
