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
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/spdx/tools-golang/spdx/v2/v2_2"
)

type spdxTypeGuesser struct{}

func (_ *spdxTypeGuesser) GuessDocumentType(blob []byte, format processor.FormatType) processor.DocumentType {
	spdxDoc := &v2_2.Document{}
	switch format {
	case processor.FormatJSON:
		if err := spdxDoc.UnmarshalJSON(blob); err == nil {
			// This is set to check for DocumentNamespace since there seem to
			// be some SBOMs in the wild that don't use certain fields like
			// document name.
			// https://github.com/guacsec/guac/issues/743
			if spdxDoc.DocumentNamespace != "" {
				return processor.DocumentSPDX
			}
		}
	}
	return processor.DocumentUnknown
}
