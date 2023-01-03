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
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	attestation_vuln "github.com/guacsec/guac/pkg/certifier/attestation"
	"github.com/guacsec/guac/pkg/handler/processor"
)

func existAndPop(nodes []*processor.DocumentNode, n *processor.DocumentNode) bool {
	for i, nn := range nodes {
		if DocTreeEqual(nn, n) {
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
	if a == nil || b == nil {
		return false
	}

	// check if a and b Documents are equal
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

// ConsistentJsonBytes makes sure that the blob byte comparison
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

func DocEqualWithTimestamp(gotDoc, wantDoc *processor.Document) (bool, error) {
	var testTime = time.Unix(1597826280, 0)

	got, err := parseVulnCertifyPredicate(gotDoc.Blob)
	if err != nil {
		return false, fmt.Errorf("failed to unmarshal json: %s", err)
	}

	want, err := parseVulnCertifyPredicate(wantDoc.Blob)
	if err != nil {
		return false, fmt.Errorf("failed to unmarshal json: %s", err)
	}

	// change the timestamp to match else it will fail to compare
	want.Predicate.Metadata.ScannedOn = &testTime
	got.Predicate.Metadata.ScannedOn = &testTime

	return reflect.DeepEqual(want, got), nil
}

func parseVulnCertifyPredicate(p []byte) (*attestation_vuln.VulnerabilityStatement, error) {
	predicate := attestation_vuln.VulnerabilityStatement{}
	if err := json.Unmarshal(p, &predicate); err != nil {
		return nil, err
	}
	return &predicate, nil
}
