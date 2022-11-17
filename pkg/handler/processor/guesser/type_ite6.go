//
// Copyright 2022 The GUAC Authors.
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

package guesser

import (
	"encoding/json"
	"strings"

	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/in-toto/in-toto-golang/in_toto"
)

type ite6TypeGuesser struct{}

func (_ *ite6TypeGuesser) GuessDocumentType(blob []byte, format processor.FormatType) processor.DocumentType {
	var statement in_toto.Statement
	if json.Unmarshal(blob, &statement) == nil && format == processor.FormatJSON {
		if strings.HasPrefix(statement.Type, "https://in-toto.io/Statement") {
			if strings.HasPrefix(statement.PredicateType, "https://slsa.dev/provenance") {
				return processor.DocumentITE6SLSA
			} else if strings.HasPrefix(statement.PredicateType, "https://crev.dev/in-toto-scheme") {
				return processor.DocumentITE6Generic
			} else if strings.HasPrefix(statement.PredicateType, "https://in-toto.io/attestation/certify/v0.1") {
				return processor.DocumentITE6Generic
			} else if strings.HasPrefix(statement.PredicateType, "http://in-toto.io/attestation/vuln/v0.1") {
				return processor.DocumentITE6Vul
			}
			return processor.DocumentITE6Generic
		}
	}
	return processor.DocumentUnknown
}
