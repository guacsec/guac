//
// Copyright 2021 The AFF Authors.
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

package processor

import (
	"encoding/json"
	"fmt"
)

// TODO: Move to internal

// simpleDocProc is a document processor for a simple docment
// It is of JSON blob type
//
// It should have an issuer field, that should match up with
// issuer URI in TrustInformation
//
// SourceInformation should be propagated
//
// Schema check should include:
// issuer (required) - string
// info (optional) - string
// nested - list of objects that match currnet schema
//
// and no other fields
//
// Example object is
// {
// 	"issuer": "google.com",
// 	"info": "this is a cool document"
// }
//
// Example object with nested is
// {
// 	"issuer": "google.com",
// 	"info": "this is a cool document",
// 	"nested": [{
// 		"issuer": "google.com",
// 		"info": "this is a cooler nested doc 1"
// 	},{
// 		"issuer": "google.com",
// 		"info": "this is a cooler nested doc 2"
//  }]
// }
type simpleDocProc struct{}

const (
	simpleDocType DocumentType = "simple-doc"
)

type simpleDoc struct {
	Issuer string      `json:"issuer"`
	Info   string      `json:"info,omitempty"`
	Nested []simpleDoc `json:"nested,omitempty"`
}

func (dp *simpleDocProc) ValidateSchema(d *Document) error {
	if d.Format != FormatJSON {
		return fmt.Errorf("only accept JSON formats")
	}

	var p simpleDoc
	if err := json.Unmarshal(d.Blob, &p); err != nil {
		return err
	}

	return validateSimpleDoc(p)
}

func validateSimpleDoc(pd simpleDoc) error {
	if pd.Issuer == "" {
		return fmt.Errorf("issuer shouldn't be empty")
	}
	for _, nestedDoc := range pd.Nested {
		if err := validateSimpleDoc(nestedDoc); err != nil {
			return err
		}
	}
	return nil
}

func (dp *simpleDocProc) ValidateTrustInformation(d *Document) (map[string]interface{}, error) {
	var p simpleDoc
	if err := json.Unmarshal(d.Blob, &p); err != nil {
		return nil, err
	}

	trustInfo := map[string]interface{}{}
	if d.TrustInformation.IssuerUri != nil {
		if p.Issuer != *d.TrustInformation.IssuerUri {
			return nil, fmt.Errorf("trust information not valid issuer doesn't match")
		}
		trustInfo["issuer"] = d.TrustInformation.IssuerUri
	}
	return trustInfo, nil
}

func (dp *simpleDocProc) Unpack(d *Document) ([]*Document, error) {
	var p simpleDoc
	if err := json.Unmarshal(d.Blob, &p); err != nil {
		return nil, err
	}

	retDocs := make([]*Document, len(p.Nested))
	for i, nd := range p.Nested {
		b, err := json.Marshal(nd)
		if err != nil {
			return nil, err
		}
		retDocs[i] = &Document{
			Blob:             b,
			Type:             simpleDocType,
			Format:           FormatJSON,
			TrustInformation: d.TrustInformation,
		}
	}

	return retDocs, nil
}

/*
func goodSimpleDoc(issuer string, info string) Document {
	b, _ := json.Marshal(simpleDoc{
		Issuer: issuer,
		Info:   info,
	})

	return Document{
		Blob:   b,
		Type:   simpleDocType,
		Format: FormatJSON,
		TrustInformation: TrustInformation{
			IssuerUri: &issuer,
		},
		SourceInformation: d.SourceInformation,
	}
}
*/
