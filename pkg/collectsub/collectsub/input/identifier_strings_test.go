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

// input defines collectsub structs that can be used for human/application inputs
// that do not necessarily find it convenient to use protobuf (e.g.
package input

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	pb "github.com/guacsec/guac/pkg/collectsub/collectsub"
	parser_common "github.com/guacsec/guac/pkg/ingestor/parser/common"
)

func Test_IdentifierStringsSliceToCollectEntries(t *testing.T) {
	testCases := []struct {
		name     string
		input    []*parser_common.IdentifierStrings
		expected []*pb.CollectEntry
	}{{
		name: "simple test",
		input: []*parser_common.IdentifierStrings{
			{
				OciStrings: []string{"index.docker.io/guacsec/local-organic-guac"},
				VcsStrings: []string{"git+https://github.com/guacsec/guac"},
			},
		},
		expected: []*pb.CollectEntry{
			{Type: pb.CollectDataType_DATATYPE_OCI, Value: "index.docker.io/guacsec/local-organic-guac"},
			{Type: pb.CollectDataType_DATATYPE_GIT, Value: "git+https://github.com/guacsec/guac"},
		},
	}, {
		name: "simple unclassified string test",
		input: []*parser_common.IdentifierStrings{
			{
				UnclassifiedStrings: []string{"index.docker.io/guacsec/local-organic-guac",
					"ghcr.io/guacsec/local-organic-guac",
					"https://not-oci-registry.com/guacsec/local-organic-guac",
					"gcr.io/guacsec/local-organic-guac"},
			},
		},
		expected: []*pb.CollectEntry{
			{Type: pb.CollectDataType_DATATYPE_OCI, Value: "index.docker.io/guacsec/local-organic-guac"},
			{Type: pb.CollectDataType_DATATYPE_OCI, Value: "ghcr.io/guacsec/local-organic-guac"},
			{Type: pb.CollectDataType_DATATYPE_OCI, Value: "gcr.io/guacsec/local-organic-guac"},
		},
	}, {
		name: "simple slice test",
		input: []*parser_common.IdentifierStrings{
			{
				OciStrings: []string{"index.docker.io/guacsec/local-organic-guac"},
			}, {
				VcsStrings: []string{"git+https://github.com/guacsec/guac"},
			},
		},
		expected: []*pb.CollectEntry{
			{Type: pb.CollectDataType_DATATYPE_OCI, Value: "index.docker.io/guacsec/local-organic-guac"},
			{Type: pb.CollectDataType_DATATYPE_GIT, Value: "git+https://github.com/guacsec/guac"},
		},
	}}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {

			got := IdentifierStringsSliceToCollectEntries(tt.input)
			if diff := cmp.Diff(got, tt.expected, cmpopts.EquateEmpty(), cmpopts.IgnoreUnexported(pb.CollectEntry{}), cmpopts.SortSlices(collectEntryLess)); len(diff) > 0 {
				t.Errorf("collectentries mismatch (-want +got):\n%s", diff)
				return
			}

		})
	}

}

func collectEntryLess(e1, e2 *pb.CollectEntry) bool {
	return e1.Type < e2.Type && e1.Value < e2.Value
}
