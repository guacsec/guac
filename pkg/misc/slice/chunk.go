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

package slice

import "fmt"

func Chunk[T any](slice []T, maxChunkSize int, cb func([]T) error) error {
	for start := 0; start < len(slice); start += maxChunkSize {
		end := start + maxChunkSize
		if end > len(slice) {
			end = len(slice)
		}

		if err := cb(slice[start:end]); err != nil {
			return fmt.Errorf("error running chunk callback on input slice[%d:%d]: %w", start, end, err)
		}
	}

	return nil
}
