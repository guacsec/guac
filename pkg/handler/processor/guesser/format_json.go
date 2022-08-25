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

	"github.com/guacsec/guac/pkg/handler/processor"
)

type jsonFormatGuesser struct{}

func (_ *jsonFormatGuesser) GuessFormat(blob []byte) processor.FormatType {
	if json.Valid(blob) {
		return processor.FormatJSON
	}
	return processor.FormatUnknown
}
