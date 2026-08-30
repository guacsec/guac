//
// Copyright 2026 The GUAC Authors.
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

package backend

import (
	"sort"
	"testing"

	"github.com/guacsec/guac/pkg/assembler/backends/ent"
)

// TestSortableOccurrenceCreates_DeterministicOrder verifies that sorting
// keeps each Occurrence create paired with its ID, and always produces the
// same ordering regardless of the input order. This is what prevents two
// concurrent transactions from locking shared occurrences rows in opposite
// orders (the lock-order-inversion deadlock described in the issue).
func TestSortableOccurrenceCreates_DeterministicOrder(t *testing.T) {
	idA, idB, idC := "aaaaaaaa", "bbbbbbbb", "cccccccc"
	createA, createB, createC := &ent.OccurrenceCreate{}, &ent.OccurrenceCreate{}, &ent.OccurrenceCreate{}

	orderings := [][]struct {
		id     string
		create *ent.OccurrenceCreate
	}{
		{{idC, createC}, {idA, createA}, {idB, createB}},
		{{idB, createB}, {idC, createC}, {idA, createA}},
		{{idA, createA}, {idB, createB}, {idC, createC}},
	}

	var results [][]string
	for _, ordering := range orderings {
		ids := make([]string, len(ordering))
		creates := make([]*ent.OccurrenceCreate, len(ordering))
		for i, entry := range ordering {
			ids[i] = entry.id
			creates[i] = entry.create
		}

		sort.Sort(sortableOccurrenceCreates{ids: ids, creates: creates})

		if !sort.StringsAreSorted(ids) {
			t.Fatalf("ids not sorted: %v", ids)
		}

		// Verify ids and creates stayed paired: mapping id -> create must be
		// consistent with the input mapping (A->createA, B->createB, C->createC).
		want := map[string]*ent.OccurrenceCreate{idA: createA, idB: createB, idC: createC}
		for i, id := range ids {
			if creates[i] != want[id] {
				t.Fatalf("create for id %q became mispaired after sort", id)
			}
		}

		results = append(results, append([]string(nil), ids...))
	}

	for i := 1; i < len(results); i++ {
		if len(results[i]) != len(results[0]) {
			t.Fatalf("result length mismatch: %v vs %v", results[i], results[0])
		}
		for j := range results[i] {
			if results[i][j] != results[0][j] {
				t.Fatalf("sort order differs across input orderings: %v vs %v", results[i], results[0])
			}
		}
	}
}
