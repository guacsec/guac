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
)

type attestation struct {
	Type          string `json:"_type"`
	PredicateType string `json:"predicateType"`
}

type ite6FormatGuesser struct{}

func (_ *ite6FormatGuesser) GuessFormat(blob []byte) processor.FormatType {
	var att attestation
	if json.Unmarshal(blob, &att) == nil {
		if strings.Contains(att.Type, "https://in-toto.io/Statement") {
			if strings.Contains(att.PredicateType, "https://slsa.dev/provenance") {
				return processor.FormatSLSA
			}
			return processor.FormatITE6
		}
	}
	return processor.FormatUnknown
}
