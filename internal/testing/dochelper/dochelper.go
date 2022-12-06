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

package dochelper

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/guacsec/guac/pkg/handler/processor"
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
)

func existAndPop(nodes []*processor.DocumentNode, n *processor.DocumentNode) bool {
	for i, nn := range nodes {
		if docNodeEqual(nn, n) {
			nodes = append(nodes[:i], nodes[i+1:]...) //nolint: staticcheck
			return true
		}
	}
	return false
}

func docEqual(a, b *processor.Document) bool {
	a.Blob = ConsistentJsonBytes(a.Blob)
	b.Blob = ConsistentJsonBytes(b.Blob)
	return reflect.DeepEqual(a, b)
}

func DocTreeEqual(a, b processor.DocumentTree) bool {
	return docNodeEqual(a, b)
}

func docNodeEqual(a, b *processor.DocumentNode) bool {
	if a == nil || b == nil {
		return false
	}

	// check if a and b Docuemnts are equal
	if !docEqual(a.Document, b.Document) {
		return false
	}

	// check if len of children are equal
	if len(a.Children) != len(b.Children) {
		return false
	}

	if len(a.Children) > 0 {
		// Copy list of documentNodes of A
		aCopy := make([]*processor.DocumentNode, len(a.Children))
		copy(aCopy, a.Children)

		// for each document in B, check exists and pop on listA
		// where exists and pop equivalency
		for _, bNode := range b.Children {
			if !existAndPop(aCopy, bNode) {
				return false
			}
		}
	}

	return true
}

// consistentJsonBytes makes sure that the blob byte comparison
// does not differ due to whitespace in testing definitions.
func ConsistentJsonBytes(b []byte) []byte {
	var v interface{}
	err := json.Unmarshal(b, &v)
	if err != nil {
		panic(err)
	}
	out, _ := json.Marshal(v)
	return out
}

func StringTree(n *processor.DocumentNode) string {
	return stringTreeHelper(n, "")
}

func stringTreeHelper(n *processor.DocumentNode, prefix string) string {
	str := fmt.Sprintf("%s { doc: %s, %v, %v, %v}", prefix, string(ConsistentJsonBytes(n.Document.Blob)),
		n.Document.Format,
		n.Document.Type,
		n.Document.SourceInformation,
	)
	for _, c := range n.Children {
		str += "\n" + stringTreeHelper(c, prefix+"-")
	}
	return str
}

func DocNode(v *processor.Document, children ...*processor.DocumentNode) *processor.DocumentNode {
	return &processor.DocumentNode{
		Document: v,
		Children: children,
	}
}
