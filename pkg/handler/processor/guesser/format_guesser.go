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
	_ = RegisterDocumentFormatGuesser(&jsonFormatGuesser{}, "json")
}

// DocumentFormatGuesser guesses the format of the document given a blob
type DocumentFormatGuesser interface {
	// GuessFormat returns the format type guessed to processor.FormatUnknown if
	// it is unable to.
	GuessFormat(blob []byte) processor.FormatType
}

var (
	documentFormatGuessers = map[string]DocumentFormatGuesser{}
)

func RegisterDocumentFormatGuesser(g DocumentFormatGuesser, name string) error {
	if _, ok := documentFormatGuessers[name]; ok {
		return fmt.Errorf("the document type guesser is being overwritten: %s", name)
	}
	documentFormatGuessers[name] = g

	return nil
}
