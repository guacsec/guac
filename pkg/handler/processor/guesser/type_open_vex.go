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

package guesser

import (
	"github.com/openvex/go-vex/pkg/vex"

	"github.com/guacsec/guac/pkg/handler/processor"
)

type openVexTypeGuesser struct{}

func (_ *openVexTypeGuesser) GuessDocumentType(blob []byte, format processor.FormatType) processor.DocumentType {
	switch format {
	case processor.FormatJSON:
		// Decode the BOM
		var decoded vex.VEX
		err := json.Unmarshal(blob, &decoded)
		if err == nil && decoded.Metadata.ID != "" {
			return processor.DocumentOpenVEX
		}
	}
	return processor.DocumentUnknown
}
