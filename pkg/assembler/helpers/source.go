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
	"strings"

	"github.com/guacsec/guac/pkg/assembler/clients/generated"
)

func ConcatenateSourceInput(source *generated.SourceInputSpec) string {
	var sourceElements []string
	sourceElements = append(sourceElements, source.Type, source.Namespace, source.Name)
	if source.Tag != nil {
		sourceElements = append(sourceElements, *source.Tag)
	}
	if source.Commit != nil {
		sourceElements = append(sourceElements, *source.Commit)
	}
	return strings.Join(sourceElements, "/")
}
