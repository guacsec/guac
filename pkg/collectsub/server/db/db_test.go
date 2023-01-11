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

package db

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	pb "github.com/guacsec/guac/pkg/collectsub/collectsub"
	"github.com/guacsec/guac/pkg/collectsub/server/db/simpledb"
	"github.com/guacsec/guac/pkg/collectsub/server/db/types"
)

func Test_SimpleDb_AddGetCollectEntries(t *testing.T) {
	tests := []struct {
		name  string
		calls []testCall
	}{{
		name: "simple add/get",
		calls: []testCall{
			// initial DB empty
			getFn([]*pb.CollectEntryFilter{}, false, []*pb.CollectEntry{}),
			// add single OCI entry
			addFn([]*pb.CollectEntry{
				{Type: pb.CollectDataType_DATATYPE_OCI, Value: "oci://abc"},
			}, false),
			// retrieve all entries for OCI
			getFn([]*pb.CollectEntryFilter{
				{Type: pb.CollectDataType_DATATYPE_OCI, Glob: "*"},
			}, false, []*pb.CollectEntry{
				{Type: pb.CollectDataType_DATATYPE_OCI, Value: "oci://abc"},
			}),
			// retrieve all entries for GIT should not return any results
			getFn([]*pb.CollectEntryFilter{
				{Type: pb.CollectDataType_DATATYPE_GIT, Glob: "*"},
			}, false, []*pb.CollectEntry{}),
		},
	}, {
		name: "multiple add/get",
		calls: []testCall{
			// initial DB empty
			getFn([]*pb.CollectEntryFilter{}, false, []*pb.CollectEntry{}),
			// add single OCI entry
			addFn([]*pb.CollectEntry{
				{Type: pb.CollectDataType_DATATYPE_OCI, Value: "oci://abc"},
			}, false),
			// add single OCI entry
			addFn([]*pb.CollectEntry{
				{Type: pb.CollectDataType_DATATYPE_OCI, Value: "oci://def"},
			}, false),

			// add multiple OCI entry
			addFn([]*pb.CollectEntry{
				{Type: pb.CollectDataType_DATATYPE_OCI, Value: "oci://xxx"},
				{Type: pb.CollectDataType_DATATYPE_OCI, Value: "oci://yyy"},
				{Type: pb.CollectDataType_DATATYPE_OCI, Value: "oci://zzz"},
			}, false),

			// retrieve all entries for OCI
			getFn([]*pb.CollectEntryFilter{
				{Type: pb.CollectDataType_DATATYPE_OCI, Glob: "*"},
			}, false, []*pb.CollectEntry{
				{Type: pb.CollectDataType_DATATYPE_OCI, Value: "oci://abc"},
				{Type: pb.CollectDataType_DATATYPE_OCI, Value: "oci://def"},
				{Type: pb.CollectDataType_DATATYPE_OCI, Value: "oci://xxx"},
				{Type: pb.CollectDataType_DATATYPE_OCI, Value: "oci://yyy"},
				{Type: pb.CollectDataType_DATATYPE_OCI, Value: "oci://zzz"},
			}),
		},
	}, {
		name: "test entry filters",
		calls: []testCall{
			// initial DB empty
			getFn([]*pb.CollectEntryFilter{}, false, []*pb.CollectEntry{}),
			// add single OCI entry
			addFn([]*pb.CollectEntry{
				{Type: pb.CollectDataType_DATATYPE_OCI, Value: "oci://abc"},
			}, false),
			// add single GIT entry
			addFn([]*pb.CollectEntry{
				{Type: pb.CollectDataType_DATATYPE_GIT, Value: "git+https://github.com/guacsec/guac"},
			}, false),

			// retrieve all entries for OCI
			getFn([]*pb.CollectEntryFilter{
				{Type: pb.CollectDataType_DATATYPE_OCI, Glob: "*"},
			}, false, []*pb.CollectEntry{
				{Type: pb.CollectDataType_DATATYPE_OCI, Value: "oci://abc"},
			}),

			// retrieve oci://a prefix for OCI
			getFn([]*pb.CollectEntryFilter{
				{Type: pb.CollectDataType_DATATYPE_OCI, Glob: "oci://a*"},
			}, false, []*pb.CollectEntry{
				{Type: pb.CollectDataType_DATATYPE_OCI, Value: "oci://abc"},
			}),

			// retrieve oci://abc prefix for OCI
			getFn([]*pb.CollectEntryFilter{
				{Type: pb.CollectDataType_DATATYPE_OCI, Glob: "oci://abc*"},
			}, false, []*pb.CollectEntry{
				{Type: pb.CollectDataType_DATATYPE_OCI, Value: "oci://abc"},
			}),

			// retrieve oci://def prefix for OCI
			getFn([]*pb.CollectEntryFilter{
				{Type: pb.CollectDataType_DATATYPE_OCI, Glob: "oci://def*"},
			}, false, []*pb.CollectEntry{}),

			// retrieve git prefix for OCI which should not return
			getFn([]*pb.CollectEntryFilter{
				{Type: pb.CollectDataType_DATATYPE_OCI, Glob: "git*"},
			}, false, []*pb.CollectEntry{}),
		},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.TODO()
			db, err := simpledb.NewSimpleDb()
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range tt.calls {
				if err := c(ctx, db); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

type testCall func(ctx context.Context, db types.CollectSubscriberDb) error

func getFn(filters []*pb.CollectEntryFilter, expectErr bool, expect []*pb.CollectEntry) testCall {
	return func(ctx context.Context, db types.CollectSubscriberDb) error {
		entries, err := db.GetCollectEntries(ctx, filters)
		if err != nil != expectErr {
			return fmt.Errorf("expected err status %v, got %v", expectErr, err != nil)
		}

		if err != nil {
			return fmt.Errorf("unexpected err: %v", err)
		}
		// Check if entries are equal to expected and return error otherwise
		if !entriesEqual(entries, expect) {
			return fmt.Errorf("entries did not match, got %v, expected %v", entries, expect)
		}

		return nil

	}
}

func addFn(entries []*pb.CollectEntry, expectErr bool) testCall {
	return func(ctx context.Context, db types.CollectSubscriberDb) error {
		err := db.AddCollectEntries(ctx, entries)
		if err != nil != expectErr {
			return fmt.Errorf("expected err status %v, got %v", expectErr, err != nil)
		}
		return nil
	}
}

// Helper function fuzzy equal for tests
func entriesEqual(e1, e2 []*pb.CollectEntry) bool {
	trans := cmp.Transformer("canonicalize", canonicalize)

	return cmp.Equal(e1, e2, cmpopts.EquateEmpty(), trans, cmpopts.SortSlices(entryCmp))
}

func entryCmp(e1, e2 *pb.CollectEntry) bool {
	return canonicalize(e1) < canonicalize(e2)
}

func canonicalize(e *pb.CollectEntry) string {
	return fmt.Sprintf("%v:%v", e.GetType(), e.GetValue())
}
