//
// Copyright 2024 The GUAC Authors.
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

package pagination_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	models "github.com/guacsec/guac/pkg/guacrest/generated"
	"github.com/guacsec/guac/pkg/guacrest/pagination"
)

// Uses Paginate to test the cursor implementation
func Test_Cursors(t *testing.T) {
	ctx := context.Background()
	inputList := []int{12, 13, 14, 15, 16, 17}

	for i := range inputList {
		spec := models.PaginationSpec{PageSize: pagination.PointerOf(i)}
		_, info, err := pagination.Paginate(ctx, inputList, &spec)
		if err != nil {
			t.Fatalf("Unexpected error when calling Paginate to retrieve a cursor: %s", err)
		}
		if info.NextCursor == nil {
			t.Fatalf("info.NextCursor is nil after calling Paginate to retrieve a cursor")
		}

		// check that spec.NextCursor does point to the next element
		spec = models.PaginationSpec{
			PageSize: pagination.PointerOf(100),
			Cursor:   info.NextCursor,
		}
		page, _, err := pagination.Paginate(ctx, inputList, &spec)
		if err != nil {
			t.Fatalf("Unexpected error (%s) when calling Paginate to retrieve an element"+
				" at index %d.", err, i)
		}
		if page[0] != inputList[i] {
			t.Errorf("Cursor points to wrong value: page[0] != inputList[i]: %v != %v.",
				page[0], inputList[i])
		}
	}
}

// Paginate is black-box tested by first retrieving some cursors, and then using
// them to test different combinations of PaginationSpec. This avoids testing
// the implementation of the cursors.
func Test_Paginate(t *testing.T) {
	ctx := context.Background()

	inputList := []int{12, 13, 14, 15, 16, 17}

	// cursors[i] holds the cursor to inputList[i]
	cursors := []string{}
	for i := range inputList {
		spec := models.PaginationSpec{PageSize: pagination.PointerOf(i)}
		_, info, err := pagination.Paginate(ctx, inputList, &spec)
		if err != nil {
			t.Fatalf("Unexpected error when calling Paginate to set up the tests: %s", err)
		}
		if info.NextCursor == nil {
			t.Fatalf("info.NextCursor is nil after calling Paginate to set up the tests")
		}
		cursors = append(cursors, *info.NextCursor)
	}

	// generate a cursor that is out of range of inputList
	longerInputList := append(inputList, 18)
	spec := models.PaginationSpec{PageSize: pagination.PointerOf(6)}
	_, info, err := pagination.Paginate(ctx, longerInputList, &spec)
	if err != nil {
		t.Fatalf("Unexpected error when calling Paginate to set up the"+
			" out-of-range cursor test: %s", err)
	}
	// check that we got a valid cursor
	outOfRangeCursor := info.NextCursor
	if outOfRangeCursor == nil {
		t.Fatal("Unexpected cursor when calling Paginate to set up the" +
			" out-of-range cursor test: Cursor is empty.")
	}

	tests := []struct {
		name                   string
		inputSpec              *models.PaginationSpec
		expectedPage           []int
		expectedPaginationInfo models.PaginationInfo
		wantErr                bool
	}{
		{
			name:         "PaginationSpec is nil, default is used",
			expectedPage: inputList,
			expectedPaginationInfo: models.PaginationInfo{
				TotalCount: pagination.PointerOf(6),
			},
		},
		{
			name:         "Only PageSize specified",
			inputSpec:    &models.PaginationSpec{PageSize: pagination.PointerOf(3)},
			expectedPage: []int{12, 13, 14},
			expectedPaginationInfo: models.PaginationInfo{
				TotalCount: pagination.PointerOf(6),
				NextCursor: &cursors[3],
			},
		},
		{
			name:         "PageSize is greater than the number of entries",
			inputSpec:    &models.PaginationSpec{PageSize: pagination.PointerOf(10)},
			expectedPage: inputList,
			expectedPaginationInfo: models.PaginationInfo{
				TotalCount: pagination.PointerOf(6),
			},
		},
		{
			name:         "PageSize is equal to the number of entries",
			inputSpec:    &models.PaginationSpec{PageSize: pagination.PointerOf(6)},
			expectedPage: inputList,
			expectedPaginationInfo: models.PaginationInfo{
				TotalCount: pagination.PointerOf(6),
			},
		},
		{
			name:         "PageSize is 0",
			inputSpec:    &models.PaginationSpec{PageSize: pagination.PointerOf(0)},
			expectedPage: []int{},
			expectedPaginationInfo: models.PaginationInfo{
				TotalCount: pagination.PointerOf(6),
				NextCursor: &cursors[0],
			},
		},
		{
			name:      "PageSize is negative",
			inputSpec: &models.PaginationSpec{PageSize: pagination.PointerOf(-1)},
			wantErr:   true,
		},
		{
			name: "PageSize is in range, Cursor is valid",
			inputSpec: &models.PaginationSpec{
				PageSize: pagination.PointerOf(2),
				Cursor:   pagination.PointerOf(cursors[2]),
			},
			expectedPage: []int{14, 15},
			expectedPaginationInfo: models.PaginationInfo{
				TotalCount: pagination.PointerOf(6),
				NextCursor: &cursors[4],
			},
		},
		{
			name: "PageSize is 1, Cursor is valid",
			inputSpec: &models.PaginationSpec{
				PageSize: pagination.PointerOf(1),
				Cursor:   pagination.PointerOf(cursors[5]),
			},
			expectedPage: []int{17},
			expectedPaginationInfo: models.PaginationInfo{
				TotalCount: pagination.PointerOf(6),
			},
		},
		{
			name: "PageSize + Cursor is greater than number of entries",
			inputSpec: &models.PaginationSpec{
				PageSize: pagination.PointerOf(3),
				Cursor:   pagination.PointerOf(cursors[4]),
			},
			expectedPage: []int{16, 17},
			expectedPaginationInfo: models.PaginationInfo{
				TotalCount: pagination.PointerOf(6),
			},
		},
		{
			name: "PageSize is in range, Cursor is empty string",
			inputSpec: &models.PaginationSpec{
				PageSize: pagination.PointerOf(3),
				Cursor:   pagination.PointerOf(""),
			},
			wantErr: true,
		},
		{
			name: "PageSize is in range, Cursor is invalid base64",
			inputSpec: &models.PaginationSpec{
				PageSize: pagination.PointerOf(3),
				Cursor:   pagination.PointerOf("$%^"),
			},
			wantErr: true,
		},
		{
			name: "PageSize is in range, Cursor is too large",
			inputSpec: &models.PaginationSpec{
				PageSize: pagination.PointerOf(3),
				Cursor:   pagination.PointerOf("ABCDABCDABCD"),
			},
			wantErr: true,
		},
		{
			name: "PageSize is in range, Cursor is too small",
			inputSpec: &models.PaginationSpec{
				PageSize: pagination.PointerOf(3),
				Cursor:   pagination.PointerOf("ABC"),
			},
			wantErr: true,
		},
		{
			name: "Cursor is out of range",
			inputSpec: &models.PaginationSpec{
				Cursor: outOfRangeCursor,
			},
			wantErr: true,
		},
		{
			name: "PageSize is not specified",
			inputSpec: &models.PaginationSpec{
				Cursor: pagination.PointerOf(cursors[1]),
			},
			expectedPage: []int{13, 14, 15, 16, 17},
			expectedPaginationInfo: models.PaginationInfo{
				TotalCount: pagination.PointerOf(6),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			page, info, err := pagination.Paginate(ctx, inputList, tt.inputSpec)
			if (err != nil) != tt.wantErr {
				t.Fatalf("tt.wantErr is %v, but got %v", tt.wantErr, err)
				return
			}
			if !cmp.Equal(tt.expectedPage, page) {
				t.Errorf("Wrong page. Expected %v, but got %v", tt.expectedPage, page)
			}
			if !cmp.Equal(tt.expectedPaginationInfo, info) {
				t.Errorf("Wrong paginationInfo. Expected %v, but got %v", tt.expectedPaginationInfo, info)
			}
		})

	}

}
