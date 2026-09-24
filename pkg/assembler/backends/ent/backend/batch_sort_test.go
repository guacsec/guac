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
	"slices"
	"sort"
	"testing"

	"github.com/guacsec/guac/pkg/assembler/backends/ent"
)

func assertSortBatchByIDDeterministic[T comparable](t *testing.T, newCreate func() T) {
	t.Helper()
	idA, idB, idC := "aaaaaaaa", "bbbbbbbb", "cccccccc"
	want := map[string]T{idA: newCreate(), idB: newCreate(), idC: newCreate()}

	orderings := [][]string{
		{idC, idA, idB},
		{idB, idC, idA},
		{idA, idB, idC},
	}

	var first []string
	for _, ordering := range orderings {
		ids := slices.Clone(ordering)
		creates := make([]T, len(ids))
		for i, id := range ids {
			creates[i] = want[id]
		}

		sortBatchByID(ids, creates)

		if !sort.StringsAreSorted(ids) {
			t.Fatalf("ids not sorted: %v", ids)
		}
		for i, id := range ids {
			if creates[i] != want[id] {
				t.Fatalf("create for id %q became mispaired after sort", id)
			}
		}
		if first == nil {
			first = ids
		} else if !slices.Equal(ids, first) {
			t.Fatalf("sort order differs across input orderings: %v vs %v", ids, first)
		}
	}
}

func TestSortBatchByID_DeterministicOrder(t *testing.T) {
	t.Run("PackageName", func(t *testing.T) {
		assertSortBatchByIDDeterministic(t, func() *ent.PackageNameCreate { return &ent.PackageNameCreate{} })
	})
	t.Run("Occurrence", func(t *testing.T) {
		assertSortBatchByIDDeterministic(t, func() *ent.OccurrenceCreate { return &ent.OccurrenceCreate{} })
	})
	t.Run("CertifyLegal", func(t *testing.T) {
		assertSortBatchByIDDeterministic(t, func() *ent.CertifyLegalCreate { return &ent.CertifyLegalCreate{} })
	})
}
