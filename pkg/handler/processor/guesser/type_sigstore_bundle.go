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
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
)

type sigstoreBundleTypeGuesser struct{}

func (_ *sigstoreBundleTypeGuesser) GuessDocumentType(blob []byte, format processor.FormatType) processor.DocumentType {

	if format == processor.FormatJSON {
		var bundle bundle.Bundle
		bundle.Bundle = new(protobundle.Bundle)

		if err := bundle.UnmarshalJSON(blob); err == nil {
			return processor.DocumentSigstoreBundle
		}
	}
	return processor.DocumentUnknown
}
