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

package bundle

import (
	"fmt"

	"github.com/guacsec/guac/pkg/handler/processor"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
)

type BundleProcessor struct {
}

func (d *BundleProcessor) ValidateSchema(i *processor.Document) error {
	if i.Type != processor.DocumentSigstoreBundle {
		return fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentSigstoreBundle, i.Type)
	}

	_, err := parseBundle(i.Blob)

	return err
}

// Unpack takes in the document and tries to unpack it
// if there is a valid decomposition of sub-documents.
//
// For example, a DSSE envelope or a tarball
// Returns empty list and nil error if nothing to unpack
// Returns unpacked list and nil error if successfully unpacked
func (d *BundleProcessor) Unpack(i *processor.Document) ([]*processor.Document, error) {
	if i.Type != processor.DocumentSigstoreBundle {
		return nil, fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentSigstoreBundle, i.Type)
	}

	bundle, err := parseBundle(i.Blob)
	if err != nil {
		return nil, err
	}

	doc := &processor.Document{
		Blob:              bundle.GetDsseEnvelope().Payload,
		Type:              processor.DocumentUnknown,
		Format:            processor.FormatUnknown,
		SourceInformation: i.SourceInformation,
	}

	return []*processor.Document{doc}, nil
}

func parseBundle(b []byte) (*bundle.Bundle, error) {
	var bundle bundle.Bundle
	bundle.Bundle = new(protobundle.Bundle)

	if err := bundle.UnmarshalJSON(b); err != nil {
		return nil, fmt.Errorf("failed to unmarshal json bundle with error: %w", err)
	}
	return &bundle, nil
}
