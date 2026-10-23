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
	"fmt"

	"github.com/guacsec/guac/pkg/handler/processor"
)

func init() {
	_ = RegisterDocumentTypeGuesser(&ite6TypeGuesser{}, "ite6")
	_ = RegisterDocumentTypeGuesser(&dsseTypeGuesser{}, "dsse")
	_ = RegisterDocumentTypeGuesser(&spdxTypeGuesser{}, "spdx")
	_ = RegisterDocumentTypeGuesser(&scorecardTypeGuesser{}, "scorecard")
	_ = RegisterDocumentTypeGuesser(&cycloneDXTypeGuesser{}, "cyclonedx")
	_ = RegisterDocumentTypeGuesser(&openVexTypeGuesser{}, "openvex")
	_ = RegisterDocumentTypeGuesser(&depsDevTypeGuesser{}, "deps.dev")
	_ = RegisterDocumentTypeGuesser(&csafTypeGuesser{}, "csaf")
}

// DocumentTypeGuesser guesses the document type based on the blob and format given
type DocumentTypeGuesser interface {
	// GuessDocumentType returns the document type guessed or processor.DocumentUnknown if
	// it is unable to. Format provided may be processor.FormatUnknown.
	GuessDocumentType(blob []byte, format processor.FormatType) processor.DocumentType
}

var (
	documentTypeGuessers = map[string]DocumentTypeGuesser{}
)

func RegisterDocumentTypeGuesser(g DocumentTypeGuesser, name string) error {
	if _, ok := documentTypeGuessers[name]; ok {
		documentTypeGuessers[name] = g
		return fmt.Errorf("the document type guesser is being overwritten: %s", name)
	}
	documentTypeGuessers[name] = g
	return nil
}
