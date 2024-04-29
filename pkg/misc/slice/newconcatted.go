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

// NewConcatted returns a new slice whose elements are the elements of all of
// its params concatenated together.
func NewConcatted[T any](slices ...[]T) []T {
	return newConcatted(nil, nil, slices...)
}

func newConcatted[T any](checkBeforeLenAndCap func(len, cap int), checkAfterLenAndCap func(len, cap int), slices ...[]T) []T {
	if len(slices) == 0 {
		return nil
	}

	newLen, newCap := 0, 0
	for _, slice := range slices {
		newCap += len(slice)
	}

	newSlice := make([]T, newLen, newCap)

	if checkBeforeLenAndCap != nil {
		checkBeforeLenAndCap(len(newSlice), cap(newSlice))
	}

	for _, slice := range slices {
		newSlice = append(newSlice, slice...)
	}

	if checkAfterLenAndCap != nil {
		checkAfterLenAndCap(len(newSlice), cap(newSlice))
	}

	return newSlice
}
