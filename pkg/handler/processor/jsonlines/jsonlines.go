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

package jsonlines

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/handler/processor/dsse"
	"github.com/guacsec/guac/pkg/handler/processor/guesser"
)

type JsonLinesProcessor struct{}

func (d *JsonLinesProcessor) ValidateSchema(i *processor.Document) error {
	if i.Type != processor.DocumentJsonLines {
		return fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentJsonLines, i.Type)
	}

	_, err := parseJsonLines(i.Blob)
	return err
}

// Unpack takes in the document and tries to unpack it
// if there is a valid decomposition of sub-documents.
//
// For example, a DSSE envelope or a tarball
// Returns empty list and nil error if nothing to unpack
// Returns unpacked list and nil error if successfully unpacked
func (d *JsonLinesProcessor) Unpack(i *processor.Document) ([]*processor.Document, error) {
	if i.Type != processor.DocumentJsonLines {
		return nil, fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentJsonLines, i.Type)
	}

	lines, err := parseJsonLines(i.Blob)
	if err != nil {
		return nil, err
	}

	documents := []*processor.Document{}
	for _, line := range lines {
		doc := &processor.Document{
			Blob:              line,
			Type:              processor.DocumentUnknown,
			Format:            processor.FormatJSON,
			SourceInformation: i.SourceInformation,
		}
		docType, _, err := guesser.GuessDocument(doc)
		if err != nil {
			return nil, err
		}
		doc.Type = docType
		switch docType {
		case processor.DocumentDSSE:
			var p dsse.DSSEProcessor
			unpacked, err := p.Unpack(doc)
			if err != nil {
				return nil, err
			}
			documents = append(documents, unpacked...)
		default:
			documents = append(documents, doc)
		}
	}
	return documents, nil
}

func parseJsonLines(b []byte) ([][]byte, error) {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	blines := [][]byte{}
	for idx, line := range lines {
		bline := []byte(strings.TrimSpace(line))
		if !json.Valid(bline) {
			return nil, fmt.Errorf("unable to parse JSON Lines file. line %d is invalid json", idx)
		}
		blines = append(blines, bline)
	}
	return blines, nil
}
