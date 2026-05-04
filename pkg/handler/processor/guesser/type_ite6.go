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

	"github.com/guacsec/guac/pkg/handler/processor"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

// ite6Statement supports unmarshalling both v0.1 ("_type", "predicateType")
// and v1 ("type", "predicate_type") in-toto statement formats.
type ite6Statement struct {
	TypeV01          string `json:"_type"`
	PredicateTypeV01 string `json:"predicateType"`
	TypeV1           string `json:"type"`
	PredicateTypeV1  string `json:"predicate_type"`
}

// getType returns the statement type from whichever format was used.
// in-toto v1 is the current standard; v0.1 is supported for backwards
// compatibility. A document that populates both _type and type is malformed.
func (s *ite6Statement) getType() string {
	if s.TypeV1 != "" && s.TypeV01 != "" {
		// Both fields set: reject the ambiguous/malformed document.
		return ""
	}
	if s.TypeV1 != "" {
		return s.TypeV1
	}
	return s.TypeV01
}

// getPredicateType returns the predicate type from whichever format was used.
// in-toto v1 is the current standard; v0.1 is supported for backwards
// compatibility. A document that populates both predicateType and predicate_type
// is malformed.
func (s *ite6Statement) getPredicateType() string {
	if s.PredicateTypeV1 != "" && s.PredicateTypeV01 != "" {
		// Both fields set: reject the ambiguous/malformed document.
		return ""
	}
	if s.PredicateTypeV1 != "" {
		return s.PredicateTypeV1
	}
	return s.PredicateTypeV01
}

type ite6TypeGuesser struct{}

func (_ *ite6TypeGuesser) GuessDocumentType(blob []byte, format processor.FormatType) processor.DocumentType {
	var statement ite6Statement
	if json.Unmarshal(blob, &statement) == nil && format == processor.FormatJSON {
		stmtType := statement.getType()
		predicateType := statement.getPredicateType()
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
			}
			return processor.DocumentITE6Generic
		}
	}
	return processor.DocumentUnknown
}
