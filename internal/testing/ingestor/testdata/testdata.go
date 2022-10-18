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
	"reflect"

	"github.com/guacsec/guac/internal/testing/ingestor/keyutil"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/key"
	"github.com/guacsec/guac/pkg/ingestor/verifier"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

var (
	// DSSE/SLSA Testdata

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
		NodeData: *assembler.NewObjectMetadata(
			processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		),
	}

	att = assembler.AttestationNode{
		FilePath: "TestSource",
		Digest:   "sha256:cf194aa4315da360a262ff73ce63e2ff68a128c3a9ee7d97163c998fd1690cec",
		NodeData: *assembler.NewObjectMetadata(
			processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		),
	}

	mat1 = assembler.ArtifactNode{
		Name:   "git+https://github.com/curl/curl-docker@master",
		Digest: "sha1:d6525c840a62b398424a78d792f457477135d0cf",
		NodeData: *assembler.NewObjectMetadata(
			processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		),
	}

	mat2 = assembler.ArtifactNode{
		Name:   "github_hosted_vm:ubuntu-18.04:20210123.1",
		Digest: "sha1:d6525c840a62b398424a78d792f457477135d0cf",
		NodeData: *assembler.NewObjectMetadata(
			processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		),
	}

	build = assembler.BuilderNode{
		BuilderType: "https://github.com/Attestations/GitHubActionsWorkflow@v1",
		BuilderId:   "https://github.com/Attestations/GitHubHostedActions@v1",
		NodeData: *assembler.NewObjectMetadata(
			processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		),
	}

	ecdsaPubKey, pemBytes, _ = keyutil.GetECDSAPubKey()
	keyHash, _               = dsse.SHA256KeyID(ecdsaPubKey)

	Ident = assembler.IdentityNode{
		ID:        "test",
		Digest:    keyHash,
		Key:       base64.StdEncoding.EncodeToString(pemBytes),
		KeyType:   "ecdsa",
		KeyScheme: "ecdsa",
		NodeData: *assembler.NewObjectMetadata(
			processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		),
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

	// SDPX Testdata

	topLevelPack = assembler.PackageNode{
		Name:   "gcr.io/google-containers/alpine-latest",
		Digest: nil,
		Purl:   "pkg:oci/alpine-latest?repository_url=gcr.io/google-containers",
		CPEs:   nil,
		Tags:   []string{"CONTAINER"},
		NodeData: *assembler.NewObjectMetadata(
			processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		),
	}

	baselayoutPack = assembler.PackageNode{
		Name:   "alpine-baselayout",
		Digest: nil,
		Purl:   "pkg:alpine/alpine-baselayout@3.2.0-r22?arch=x86_64&upstream=alpine-baselayout&distro=alpine-3.16.2",
		CPEs: []string{
			"cpe:2.3:a:alpine-baselayout:alpine-baselayout:3.2.0-r22:*:*:*:*:*:*:*",
			"cpe:2.3:a:alpine-baselayout:alpine_baselayout:3.2.0-r22:*:*:*:*:*:*:*",
		},
		NodeData: *assembler.NewObjectMetadata(
			processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		),
	}

	keysPack = assembler.PackageNode{
		Name:   "alpine-keys",
		Digest: nil,
		Purl:   "pkg:alpine/alpine-keys@2.4-r1?arch=x86_64&upstream=alpine-keys&distro=alpine-3.16.2",
		CPEs: []string{
			"cpe:2.3:a:alpine-keys:alpine-keys:2.4-r1:*:*:*:*:*:*:*",
			"cpe:2.3:a:alpine-keys:alpine_keys:2.4-r1:*:*:*:*:*:*:*",
			"cpe:2.3:a:alpine:alpine-keys:2.4-r1:*:*:*:*:*:*:*",
			"cpe:2.3:a:alpine:alpine_keys:2.4-r1:*:*:*:*:*:*:*",
		},
		NodeData: *assembler.NewObjectMetadata(
			processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		),
	}

	baselayoutdataPack = assembler.PackageNode{
		Name:   "alpine-baselayout-data",
		Digest: nil,
		Purl:   "pkg:alpine/alpine-baselayout-data@3.2.0-r22?arch=x86_64&upstream=alpine-baselayout&distro=alpine-3.16.2",
		CPEs: []string{
			"cpe:2.3:a:alpine-baselayout-data:alpine-baselayout-data:3.2.0-r22:*:*:*:*:*:*:*",
			"cpe:2.3:a:alpine-baselayout-data:alpine_baselayout_data:3.2.0-r22:*:*:*:*:*:*:*",
		},
		NodeData: *assembler.NewObjectMetadata(
			processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		),
	}

	worldFile = assembler.ArtifactNode{
		Name:   "/etc/apk/world",
		Digest: "sha256:713e3907167dce202d7c16034831af3d670191382a3e9026e0ac0a4023013201",
		Tags:   []string{"TEXT"},
		NodeData: *assembler.NewObjectMetadata(
			processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		),
	}
	rootFile = assembler.ArtifactNode{
		Name:   "/etc/crontabs/root",
		Digest: "sha256:575d810a9fae5f2f0671c9b2c0ce973e46c7207fbe5cb8d1b0d1836a6a0470e3",
		Tags:   []string{"TEXT"},
		NodeData: *assembler.NewObjectMetadata(
			processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		),
	}
	triggersFile = assembler.ArtifactNode{
		Name:   "/lib/apk/db/triggers",
		Digest: "sha256:5415cfe5f88c0af38df3b7141a3f9bc6b8178e9cf72d700658091b8f5539c7b4",
		Tags:   []string{"TEXT"},
		NodeData: *assembler.NewObjectMetadata(
			processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		),
	}
	rsaPubFile = assembler.ArtifactNode{
		Name:   "/usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-58cbb476.rsa.pub",
		Digest: "sha256:9a4cd858d9710963848e6d5f555325dc199d1c952b01cf6e64da2c15deedbd97",
		Tags:   []string{"TEXT"},
		NodeData: *assembler.NewObjectMetadata(
			processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		),
	}

	SpdxNodes = []assembler.GuacNode{topLevelPack, baselayoutPack, baselayoutdataPack, rsaPubFile, keysPack, worldFile, rootFile, triggersFile}
	SpdxEdges = []assembler.GuacEdge{
		assembler.DependsOnEdge{
			PackageNode:       topLevelPack,
			PackageDependency: baselayoutPack,
		},
		assembler.DependsOnEdge{
			PackageNode:       topLevelPack,
			PackageDependency: baselayoutdataPack,
		},
		assembler.DependsOnEdge{
			PackageNode:       topLevelPack,
			PackageDependency: keysPack,
		},
		assembler.DependsOnEdge{
			PackageNode:        topLevelPack,
			ArtifactDependency: worldFile,
		},
		assembler.DependsOnEdge{
			PackageNode:        topLevelPack,
			ArtifactDependency: rootFile,
		},
		assembler.DependsOnEdge{
			PackageNode:        topLevelPack,
			ArtifactDependency: triggersFile,
		},
		assembler.DependsOnEdge{
			PackageNode:        topLevelPack,
			ArtifactDependency: rsaPubFile,
		},
		assembler.DependsOnEdge{
			PackageNode:       baselayoutPack,
			PackageDependency: keysPack,
		},
		assembler.DependsOnEdge{
			ArtifactNode:       rootFile,
			ArtifactDependency: rsaPubFile,
		},
		assembler.ContainsEdge{
			PackageNode:       baselayoutPack,
			ContainedArtifact: rootFile,
		},
		assembler.ContainsEdge{
			PackageNode:       keysPack,
			ContainedArtifact: rsaPubFile,
		},
	}

	// CycloneDX Testdata

	cdxTopLevelPack = assembler.PackageNode{
		Name:   "gcr.io/distroless/static:nonroot",
		Digest: []string{"sha256:6ad5b696af3ca05a048bd29bf0f623040462638cb0b29c8d702cbb2805687388"},
		Purl:   "pkg:oci/static:nonroot?repository_url=gcr.io/distroless",
		CPEs:   nil,
		NodeData: *assembler.NewObjectMetadata(
			processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		),
	}

	cdxTzdataPack = assembler.PackageNode{
		Name:   "tzdata",
		Digest: nil,
		Purl:   "pkg:deb/debian/tzdata@2021a-1+deb11u6?arch=all&distro=debian-11",
		CPEs: []string{
			"cpe:2.3:a:tzdata:tzdata:2021a-1\\+deb11u6:*:*:*:*:*:*:*"},
		NodeData: *assembler.NewObjectMetadata(
			processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		),
	}

	cdxNetbasePack = assembler.PackageNode{
		Name:   "netbase",
		Digest: nil,
		Purl:   "pkg:deb/debian/netbase@6.3?arch=all&distro=debian-11",
		CPEs: []string{
			"cpe:2.3:a:netbase:netbase:6.3:*:*:*:*:*:*:*"},
		NodeData: *assembler.NewObjectMetadata(
			processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		),
	}

	cdxBasefilesPack = assembler.PackageNode{
		Name:   "base-files",
		Digest: nil,
		Purl:   "pkg:deb/debian/base-files@11.1+deb11u5?arch=amd64&distro=debian-11",
		CPEs: []string{
			"cpe:2.3:a:base-files:base-files:11.1\\+deb11u5:*:*:*:*:*:*:*"},
		NodeData: *assembler.NewObjectMetadata(
			processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		),
	}

	CycloneDXNodes = []assembler.GuacNode{cdxTopLevelPack, cdxBasefilesPack, cdxNetbasePack, cdxTzdataPack}
	CyloneDXEdges  = []assembler.GuacEdge{
		assembler.DependsOnEdge{
			PackageNode:       cdxBasefilesPack,
			PackageDependency: cdxTopLevelPack,
		},
		assembler.DependsOnEdge{
			PackageNode:       cdxNetbasePack,
			PackageDependency: cdxTopLevelPack,
		},
		assembler.DependsOnEdge{
			PackageNode:       cdxTzdataPack,
			PackageDependency: cdxTopLevelPack,
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

func GuacNodeSliceEqual(slice1, slice2 []assembler.GuacNode) bool {
	if len(slice1) != len(slice2) {
		return false
	}

	result := true

	for _, node1 := range slice1 {
		e := false
		for _, node2 := range slice2 {
			if node1.Type() == "Package" && node2.Type() == "Package" {
				if node1.(assembler.PackageNode).Name == node2.(assembler.PackageNode).Name {
					if reflect.DeepEqual(node1, node2) {
						e = true
						break
					}
				}
			} else if node1.Type() == "Artifact" && node2.Type() == "Artifact" {
				if node1.(assembler.ArtifactNode).Name == node2.(assembler.ArtifactNode).Name {
					if reflect.DeepEqual(node1, node2) {
						e = true
						break
					}
				}
			} else if node1.Type() == "Attestation" && node2.Type() == "Attestation" {
				if node1.(assembler.AttestationNode).FilePath == node2.(assembler.AttestationNode).FilePath {
					if reflect.DeepEqual(node1, node2) {
						e = true
						break
					}
				}
			} else if node1.Type() == "Builder" && node2.Type() == "Builder" {
				if node1.(assembler.BuilderNode).BuilderId == node2.(assembler.BuilderNode).BuilderId {
					if reflect.DeepEqual(node1, node2) {
						e = true
						break
					}
				}
			} else if node1.Type() == "Identity" && node2.Type() == "Identity" {
				if node1.(assembler.IdentityNode).ID == node2.(assembler.IdentityNode).ID {
					if reflect.DeepEqual(node1, node2) {
						e = true
						break
					}
				}
			}
		}
		if !e {
			result = false
			break
		}
	}
	return result
}

func GuacEdgeSliceEqual(slice1, slice2 []assembler.GuacEdge) bool {
	if len(slice1) != len(slice2) {
		return false
	}

	result := true
	for _, edge1 := range slice1 {
		e := false
		for _, edge2 := range slice2 {
			if edge1.Type() == "DependsOn" && edge2.Type() == "DependsOn" {
				if reflect.DeepEqual(edge1, edge2) {
					e = true
					break
				}
			} else if edge1.Type() == "Contains" && edge2.Type() == "Contains" {
				if reflect.DeepEqual(edge1, edge2) {
					e = true
					break
				}
			} else if edge1.Type() == "Attestation" && edge2.Type() == "Attestation" {
				if reflect.DeepEqual(edge1, edge2) {
					e = true
					break
				}
			} else if edge1.Type() == "Identity" && edge2.Type() == "Identity" {
				if reflect.DeepEqual(edge1, edge2) {
					e = true
					break
				}
			} else if edge1.Type() == "BuiltBy" && edge2.Type() == "BuiltBy" {
				if reflect.DeepEqual(edge1, edge2) {
					e = true
					break
				}
			}
		}
		if !e {
			result = false
			break
		}
	}
	return result
}
