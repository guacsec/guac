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

package backend

import (
	"entgo.io/ent/dialect/sql"
)

func IDEQ(id string) func(*sql.Selector) {
	return sql.FieldEQ("id", id)
}

func NoOpSelector() func(*sql.Selector) {
	return func(s *sql.Selector) {}
}

type Predicate interface {
	~func(*sql.Selector)
}

func optionalPredicate[P Predicate, T any](value *T, fn func(s T) P) P {
	if value == nil {
		return NoOpSelector()
	}

	return fn(*value)
}

func ptrWithDefault[T any](value *T, defaultValue T) T {
	if value == nil {
		return defaultValue
	}

	return *value
}

func toPtrSlice[T any](slice []T) []*T {
	ptrs := make([]*T, len(slice))
	for i := range slice {
		ptrs[i] = &slice[i]
	}
	return ptrs
}

func fromPtrSlice[T any](slice []*T) []T {
	ptrs := make([]T, len(slice))
	for i := range slice {
		if slice[i] == nil {
			continue
		}
		ptrs[i] = *slice[i]
	}
	return ptrs
}
