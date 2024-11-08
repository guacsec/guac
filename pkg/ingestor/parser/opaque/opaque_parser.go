//
// Copyright 2024 The GUAC Authors.
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

package opaque

// The opaque parser handles documents that dont require any parsing
// for example: json lines (.jsonl) documents that are a combination
// of other documents or perhaps documents that are not in a parsable
// format.

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
)

type parser struct {
	doc *processor.Document
}

func NewOpaqueParser() common.DocumentParser {
	return &parser{}
}

func (e *parser) initializeParser() {
	e.doc = nil
}

func (e *parser) Parse(ctx context.Context, doc *processor.Document) error {
	e.initializeParser()
	e.doc = doc

	return nil
}

func (e *parser) GetIdentities(ctx context.Context) []common.TrustInformation {
	return []common.TrustInformation{}
}

func (e *parser) GetIdentifiers(ctx context.Context) (*common.IdentifierStrings, error) {
	idstrings := &common.IdentifierStrings{}
	return idstrings, nil
}

func (e *parser) GetPredicates(ctx context.Context) *assembler.IngestPredicates {
	preds := &assembler.IngestPredicates{}
	return preds
}
