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

package processor

import "go.uber.org/zap"

type DocumentProcessor interface {
	// ValidateSchema validates the schema of the document
	ValidateSchema(i *Document) error

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
	Encoding          EncodingType
	SourceInformation SourceInformation
	ChildLogger       *zap.SugaredLogger
}

// DocumentTree describes the output of a document tree that resulted from
// processing a node
type DocumentTree *DocumentNode

// DocumentNode describes a node of a DocumentTree
type DocumentNode struct {
	Document *Document
	Children []*DocumentNode
}

// DocumentType describes the type of the document contents for schema checks
type DocumentType string

// Document* is the enumerables of DocumentType
const (
	DocumentITE6SLSA      DocumentType = "SLSA"
	DocumentITE6Generic   DocumentType = "ITE6"
	DocumentITE6Vul       DocumentType = "ITE6VUL"
	DocumentITE6EOL       DocumentType = "ITE6EOL"
	DocumentITE6Reference DocumentType = "ITE6REF"
	// ClearlyDefined
	DocumentITE6ClearlyDefined DocumentType = "ITE6CD"
	DocumentDSSE               DocumentType = "DSSE"
	DocumentSPDX               DocumentType = "SPDX"
	DocumentOpaque             DocumentType = "OPAQUE"
	DocumentScorecard          DocumentType = "SCORECARD"
	DocumentCycloneDX          DocumentType = "CycloneDX"
	DocumentDepsDev            DocumentType = "DEPS_DEV"
	DocumentCsaf               DocumentType = "CSAF"
	DocumentOpenVEX            DocumentType = "OPEN_VEX"
	DocumentIngestPredicates   DocumentType = "INGEST_PREDICATES"
	DocumentUnknown            DocumentType = "UNKNOWN"
)

// FormatType describes the document format for malform checks
type FormatType string

// Format* is the enumerables of FormatType
const (
	FormatJSON      FormatType = "JSON"
	FormatJSONLines FormatType = "JSON_LINES"
	FormatXML       FormatType = "XML"
	FormatUnknown   FormatType = "UNKNOWN"
)

type EncodingType string

const (
	EncodingBzip2   EncodingType = "BZIP2"
	EncodingZstd    EncodingType = "ZSTD"
	EncodingUnknown EncodingType = "UNKNOWN"
)

var EncodingExts = map[string]EncodingType{
	".bz2": EncodingBzip2,
	".zst": EncodingZstd,
}

// SourceInformation provides additional information about where the document comes from
type SourceInformation struct {
	// Collector describes the name of the collector providing this information
	Collector string
	// Source describes the source which the collector got this information
	Source string
	// DocumentRef describes the location of the document in the blob store
	DocumentRef string
}
