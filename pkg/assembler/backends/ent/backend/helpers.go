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
	"context"
	"crypto/sha256"
	"fmt"
	"strings"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
)

type globalID struct {
	nodeType string
	ID       string
}

func toGlobalID(nodeType string, id string) string {
	return strings.Join([]string{nodeType, id}, ":")
}

func toGlobalIDs(nodeType string, ids []string) []string {
	var globalID []string
	for _, id := range ids {
		globalID = append(globalID, strings.Join([]string{nodeType, id}, ":"))
	}
	return globalID
}

func fromGlobalID(gID string) globalID {
	idSplit := strings.Split(gID, ":")
	return globalID{
		nodeType: idSplit[0],
		ID:       idSplit[1],
	}
}

func nodeTypeFromGlobalID(ctx context.Context, gID string) (string, error) {
	idSplit := strings.Split(gID, ":")
	if len(idSplit) == 2 {
		return idSplit[0], nil
	} else {
		return "", fmt.Errorf("invalid global ID: %s", gID)
	}
}

func IDEQ(id string) func(*sql.Selector) {
	filterGlobaID := fromGlobalID(id)
	return sql.FieldEQ("id", filterGlobaID.ID)
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

// func fromPtrSlice[T any](slice []*T) []T {
// 	ptrs := make([]T, len(slice))
// 	for i := range slice {
// 		if slice[i] == nil {
// 			continue
// 		}
// 		ptrs[i] = *slice[i]
// 	}
// 	return ptrs
// }

func toLowerPtr(s *string) *string {
	if s == nil {
		return nil
	}
	lower := strings.ToLower(*s)
	return &lower
}

func chunk[T any](collection []T, size int) [][]T {
	if size <= 0 {
		panic("Second parameter must be greater than 0")
	}

	chunksNum := len(collection) / size
	if len(collection)%size != 0 {
		chunksNum += 1
	}

	result := make([][]T, 0, chunksNum)

	for i := 0; i < chunksNum; i++ {
		last := (i + 1) * size
		if last > len(collection) {
			last = len(collection)
		}
		result = append(result, collection[i*size:last])
	}

	return result
}

// generateUUIDKey is used to generate the ID based on the sha256 hash of the content of the inputSpec that is passed in.
// For example, for artifact it would be
// artifactID := uuid.NewHash(sha256.New(), uuid.NameSpaceDNS, []byte(helpers.GetKey[*model.ArtifactInputSpec, string](artInput.ArtifactInput, helpers.ArtifactServerKey)), 5)
// where the data is generated by converting the artifactInputSpec into a canonicalized key
func generateUUIDKey(data []byte) uuid.UUID {
	return uuid.NewHash(sha256.New(), uuid.NameSpaceDNS, data, 5)
}
