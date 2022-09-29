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

package testdata

import (
	"encoding/base64"
	"encoding/json"

	"github.com/guacsec/guac/internal/testing/ingestor/keyutil"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/key"
	"github.com/guacsec/guac/pkg/ingestor/verifier"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

var (
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
	Ite6DSSEDoc = processor.Document{
		Blob:   ite6Payload,
		Type:   processor.DocumentDSSE,
		Format: processor.FormatJSON,
		SourceInformation: processor.SourceInformation{
			Collector: "TestCollector",
			Source:    "TestSource",
		},
	}
	Ite6SLSADoc = processor.Document{
		Blob:   []byte(ite6SLSA),
		Type:   processor.DocumentITE6SLSA,
		Format: processor.FormatJSON,
		SourceInformation: processor.SourceInformation{
			Collector: "TestCollector",
			Source:    "TestSource",
		},
	}

	art = assembler.ArtifactNode{
		Name:   "helloworld",
		Digest: "sha256:5678...",
	}

	att = assembler.AttestationNode{
		FilePath: "TestSource",
		Digest:   "sha256:cf194aa4315da360a262ff73ce63e2ff68a128c3a9ee7d97163c998fd1690cec",
	}

	mat1 = assembler.ArtifactNode{
		Name:   "git+https://github.com/curl/curl-docker@master",
		Digest: "sha1:d6525c840a62b398424a78d792f457477135d0cf",
	}

	mat2 = assembler.ArtifactNode{
		Name:   "github_hosted_vm:ubuntu-18.04:20210123.1",
		Digest: "sha1:d6525c840a62b398424a78d792f457477135d0cf",
	}

	build = assembler.BuilderNode{
		BuilderType: "https://github.com/Attestations/GitHubActionsWorkflow@v1",
		BuilderId:   "https://github.com/Attestations/GitHubHostedActions@v1",
	}

	ecdsaPubKey, pemBytes, _ = keyutil.GetECDSAPubKey()
	keyHash, _               = dsse.SHA256KeyID(ecdsaPubKey)

	Ident = assembler.IdentityNode{
		ID:        "test",
		Digest:    keyHash,
		Key:       base64.StdEncoding.EncodeToString(pemBytes),
		KeyType:   "ecdsa",
		KeyScheme: "ecdsa",
	}

	DsseNodes = []assembler.GuacNode{Ident}
	DsseEdges = []assembler.GuacEdge{}

	SlsaNodes = []assembler.GuacNode{art, att, mat1, mat2, build}
	SlsaEdges = []assembler.GuacEdge{
		assembler.IdentityForEdge{
			IdentityNode:    Ident,
			AttestationNode: att,
		},
		assembler.BuiltByEdge{
			ArtifactNode: art,
			BuilderNode:  build,
		},
		assembler.AttestationForEdge{
			AttestationNode: att,
			ArtifactNode:    art,
		},
		assembler.DependsOnEdge{
			ArtifactNode:       art,
			ArtifactDependency: mat1,
		},
		assembler.DependsOnEdge{
			ArtifactNode:       art,
			ArtifactDependency: mat2,
		},
	}
)

type mockSigstoreVerifier struct{}

func NewMockSigstoreVerifier() *mockSigstoreVerifier {
	return &mockSigstoreVerifier{}
}

func (m *mockSigstoreVerifier) Verify(payloadBytes []byte) ([]verifier.Identity, error) {

	keyHash, _ := dsse.SHA256KeyID(ecdsaPubKey)
	return []verifier.Identity{
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

func (m *mockSigstoreVerifier) Type() verifier.VerifierType {
	return "sigstore"
}
