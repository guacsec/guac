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

package helpers

import (
	"fmt"
	"strings"

	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// collect is a simple helper to transform collections of a certain type to another type
// using the transform function func(T) R
func GetKey[T any, R any](item T, transformer func(T) R) R {
	out := transformer(item)
	return out
}

func ArtifactServerKey(input *model.ArtifactInputSpec) string {
	return artifactKey(input.Algorithm, input.Digest)
}

func ArtifactClientKey(input *generated.ArtifactInputSpec) string {
	return artifactKey(input.Algorithm, input.Digest)
}

func artifactKey(algo, digest string) string {
	return fmt.Sprintf("%s:%s", strings.ToLower(algo), strings.ToLower(digest))
}
