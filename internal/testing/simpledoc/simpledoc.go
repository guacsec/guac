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

package simpledoc

import (
	"fmt"

	"github.com/guacsec/guac/pkg/handler/processor"
	jsoniter "github.com/json-iterator/go"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

// TODO: Move to internal

// SimpleDocProc is a document processor for a simple document
// It is of JSON blob type
//
// It should have an issuer field, that should match up with
// issuer URI in TrustInformation
//
// # SourceInformation should be propagated
//
// Schema check should include:
// issuer (required) - string
// info (optional) - string
// nested - list of objects that match currnet schema
//
// and no other fields
//
// Example object is
//
//	{
//		"issuer": "google.com",
//		"info": "this is a cool document"
//	}
//
// Example object with nested is
//
//	{
//		"issuer": "google.com",
//		"info": "this is a cool document",
//		"nested": [{
//			"issuer": "google.com",
//			"info": "this is a cooler nested doc 1"
//		},{
//			"issuer": "google.com",
//			"info": "this is a cooler nested doc 2"
//	 }]
//	}
type SimpleDocProc struct{}

const (
	SimpleDocType processor.DocumentType = "simple-doc"
)

type SimpleDoc struct {
	Issuer string      `json:"issuer"`
	Info   string      `json:"info,omitempty"`
	Nested []SimpleDoc `json:"nested,omitempty"`
}

func (dp *SimpleDocProc) ValidateSchema(d *processor.Document) error {
	if d.Format != processor.FormatJSON {
		return fmt.Errorf("only accept JSON formats")
	}

	var p SimpleDoc
	if err := json.Unmarshal(d.Blob, &p); err != nil {
		return err
	}

	return validateSimpleDoc(p)
}

// Calling validateSimpleDocHelper, so that extra parameters can be passed in
func validateSimpleDoc(pd SimpleDoc) error {
	return validateSimpleDocHelper(pd, map[string]bool{})
}

func validateSimpleDocHelper(pd SimpleDoc, visited map[string]bool) error {
	if pd.Issuer == "" {
		return fmt.Errorf("issuer shouldn't be empty")
	}
	for _, nestedDoc := range pd.Nested {
		// if we've already visited this issuer, then we've already validated it
		if visited[nestedDoc.Issuer] {
			continue
		}
		// we assign this issuer as visited, and then recursively validate it
		visited[nestedDoc.Issuer] = true
		if err := validateSimpleDocHelper(nestedDoc, visited); err != nil {
			return err
		}
	}
	return nil
}

func (dp *SimpleDocProc) Unpack(d *processor.Document) ([]*processor.Document, error) {
	var p SimpleDoc
	if err := json.Unmarshal(d.Blob, &p); err != nil {
		return nil, err
	}

	retDocs := make([]*processor.Document, len(p.Nested))
	for i, nd := range p.Nested {
		b, err := json.Marshal(nd)
		if err != nil {
			return nil, err
		}
		retDocs[i] = &processor.Document{
			Blob:   b,
			Type:   SimpleDocType,
			Format: processor.FormatJSON,
		}
	}

	return retDocs, nil
}

func (_ *SimpleDocProc) GuessDocumentType(blob []byte, f processor.FormatType) processor.DocumentType {
	var p SimpleDoc
	if err := json.Unmarshal(blob, &p); err != nil {
		return processor.DocumentUnknown
	}
	if err := validateSimpleDoc(p); err != nil {
		return processor.DocumentUnknown
	}
	return SimpleDocType
}
