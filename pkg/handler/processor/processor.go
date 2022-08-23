//
// Copyright 2022 The AFF Authors.
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
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

type DocumentProcessor interface {
	ValidateSchema(i *Document) error
	ValidateTrustInformation(i *Document) (map[string]interface{}, error)

	// Unpack takes in the document and tries to unpack it
	// if there is a valid decomposition of sub-documents.
	//
	// For example, a DSSE envelope or a tarball
	// Returns list of len=0 and nil error if nothing to unpack
	// Returns unpacked list and nil error if successfully unpacked
	Unpack(i *Document) ([]*Document, error)
}

// Document describes the input for a processor to run. This input can
// come from a collector or from the processor itself (run recursively).
type Document struct {
	Blob              []byte
	Type              DocumentType
	Format            FormatType
	TrustInformation  TrustInformation
	SourceInformation SourceInformation
}

// DocumentType describes the type of the document contents for schema checks
type DocumentType string

// Document* is the enumerables of DocumentType
const (
	DocumentSLSA DocumentType = "SLSA"
	DocumentITE6              = "ITE6"
	DocumentDSSE              = "DSSE"
)

// FormatType describes the document format for malform checks
type FormatType string

// Format* is the enumerables of FormatType
const (
	FormatJSON FormatType = "JSON"
)

// TrustInformation provides additional information about how to verify the document
type TrustInformation struct {
	DSSE      *dsse.Envelope
	IssuerUri *string
	// TODO: Figure out how to handle log verification trust
	// LogVerification *rtype.LogEntryAnonVerification
}

// TrustInformation provides additional information about where the document comes from
type SourceInformation struct {
	// Collector describes the name of the collector providing this information
	Collector string
	// Source describes the source which the collector got this information
	Source string
}
