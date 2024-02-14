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

// package pagination implements a cursor-based pagination for the REST API,
// where the cursors are opaque strings that encode an index in a result set.
package pagination

import (
	"context"
	"fmt"

	models "github.com/guacsec/guac/pkg/guacrest/generated"
	"github.com/guacsec/guac/pkg/logging"
)

const (
	DefaultPageSize = 40
)

// Returns the result of Paginate with a page size of DefaultPageSize
func DefaultPaginate[T any](ctx context.Context, lst []T) ([]T, models.PaginationInfo) {
	logger := logging.FromContext(ctx)
	page, info, err := Paginate(ctx, lst, models.PaginationSpec{PageSize: PointerOf(DefaultPageSize)})
	if err != nil {
		// should not occur with the default pagination spec, see contract of Paginate
		logger.Fatalf("Pagate returned err: %s, but should not have", err)
	}
	return page, info
}

// Returns a single page from the input, selected using the given
// pagination spec, along with a struct describing the pagination of the
// returned page. The input result set should be the same for every call that
// uses chained PaginationSpecs and PaginationInfos.
//
// Errors are suitable to directly return to clients. An error is returned only if:
//   - the cursor is the empty string
//   - the cursor decodes to an out of bounds index in the input
//   - the cursor can't be decoded
//   - PageSize < 0
func Paginate[T any](ctx context.Context, lst []T, spec models.PaginationSpec) ([]T,
	models.PaginationInfo, error) {
	logger := logging.FromContext(ctx)

	var pagesize int = DefaultPageSize
	if spec.PageSize != nil {
		pagesize = *spec.PageSize
	}
	if pagesize < 0 {
		return nil, models.PaginationInfo{},
			fmt.Errorf("Pagination error: PageSize is negative.")
	}

	var inputLength uint64 = uint64(len(lst))
	var start uint64 = 0

	if spec.Cursor != nil {
		if *spec.Cursor == "" {
			return nil, models.PaginationInfo{},
				fmt.Errorf("Pagination error: The cursor is the empty string")
		}

		decoded, err := indexFromCursor(*spec.Cursor)
		if err != nil {
			logger.Warnf("Pagination error: %s", err)
			return nil, models.PaginationInfo{},
				fmt.Errorf("Pagination error: The cursor is invalid.")
		}
		if decoded >= inputLength {
			logger.Warnf("Pagination error: The cursor is out of bounds. This is" +
				" either due to client manipulation of the cursor or a different slice" +
				" argument passed to Paginate than when this cursor was generated.")
			return nil, models.PaginationInfo{},
				fmt.Errorf("Pagination error: The cursor is invalid")
		}
		start = decoded
	}

	end := start + uint64(pagesize) // end is exclusive
	nextCursor := cursorFromIndex(end)
	if end >= inputLength {
		end = inputLength
		nextCursor = ""
	}

	info := models.PaginationInfo{
		NextCursor: nextCursor,
		TotalCount: PointerOf(len(lst)),
	}
	return lst[start:end], info, nil
}

func PointerOf[T any](val T) *T { return &val }
