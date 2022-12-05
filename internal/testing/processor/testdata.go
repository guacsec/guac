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
	_ "embed"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/guacsec/guac/pkg/handler/processor"
)

var (
	// based off https://github.com/spdx/spdx-examples/blob/master/example7/spdx/example7-third-party-modules.spdx.json
	//go:embed testdata/small-spdx.json
	SpdxExampleSmall []byte

	//go:embed testdata/alpine-spdx.json
	SpdxExampleBig []byte

	//go:embed testdata/alpine-small-spdx.json
	SpdxExampleAlpine []byte

	// Invalid types for field spdxVersion
	//go:embed testdata/invalid-spdx.json
	SpdxInvalidExample []byte

	// Example scorecard
	//go:embed testdata/kubernetes-scorecard.json
	ScorecardExample []byte

	// Invalid scorecard
	//go:embed testdata/invalid-scorecard.json
	ScorecardInvalid []byte

	//go:embed testdata/alpine-cyclonedx.json
	CycloneDXExampleAlpine []byte

	//go:embed testdata/quarkus-deps-cyclonedx.json
	CycloneDXExampleQuarkusDeps []byte

	//go:embed testdata/small-deps-cyclonedx.json
	CycloneDXExampleSmallDeps []byte

	//go:embed testdata/invalid-cyclonedx.json
	CycloneDXInvalidExample []byte

	//go:embed testdata/distroless-cyclonedx.json
	CycloneDXDistrolessExample []byte

	//go:embed testdata/busybox-cyclonedx.json
	CycloneDXBusyboxExample []byte

	//go:embed testdata/big-mongo-cyclonedx.json
	CycloneDXBigExample []byte

	//go:embed testdata/crev-review.json
	ITE6CREVExample []byte

	//go:embed testdata/github-review.json
	ITE6ReviewExample []byte

	//go:embed testdata/certify-vuln.json
	ITE6VulnExample []byte
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
