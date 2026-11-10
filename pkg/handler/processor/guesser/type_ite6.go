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
	"strings"

	jsoniter "github.com/json-iterator/go"

	"github.com/guacsec/guac/internal/intoto"
	"github.com/guacsec/guac/pkg/handler/processor"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

type ite6TypeGuesser struct{}

func (*ite6TypeGuesser) GuessDocumentType(blob []byte, format processor.FormatType) processor.DocumentType {
	var statement intoto.StatementHeader
	if json.Unmarshal(blob, &statement) == nil && format == processor.FormatJSON {
		// A document that mixes the v0.1 and v1 spellings of either header
		// field is malformed: refuse to guess rather than route it on a
		// silently preferred format.
		stmtType, err := statement.Type()
		if err != nil {
			return processor.DocumentUnknown
		}
		predicateType, err := statement.PredicateType()
		if err != nil {
			return processor.DocumentUnknown
		}
		if strings.HasPrefix(stmtType, "https://in-toto.io/Statement") {
			if strings.HasPrefix(predicateType, "https://slsa.dev/provenance") {
				return processor.DocumentITE6SLSA
			} else if strings.HasPrefix(predicateType, "https://crev.dev/in-toto-scheme") {
				return processor.DocumentITE6Generic
			} else if strings.HasPrefix(predicateType, "https://in-toto.io/attestation/certify/v0.1") {
				return processor.DocumentITE6Generic
			} else if strings.HasPrefix(predicateType, "https://in-toto.io/attestation/vulns/v0.1") ||
				strings.HasPrefix(predicateType, "https://in-toto.io/attestation/vulns/v0.2") {
				return processor.DocumentITE6Vul
			} else if strings.HasPrefix(predicateType, "https://in-toto.io/attestation/clearlydefined/v0.1") {
				return processor.DocumentITE6ClearlyDefined
			} else if strings.HasPrefix(predicateType, "https://in-toto.io/attestation/malware/v0.1") {
				return processor.DocumentITE6Malware
			}
			return processor.DocumentITE6Generic
		}
	}
	return processor.DocumentUnknown
}
