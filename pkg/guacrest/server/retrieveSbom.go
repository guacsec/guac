//
// Copyright 2026 The GUAC Authors.
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

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Khan/genqlient/graphql"
	"github.com/vektah/gqlparser/v2/gqlerror"
	"gocloud.dev/gcerrors"

	gql "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/blob"
	gen "github.com/guacsec/guac/pkg/guacrest/generated"
	"github.com/guacsec/guac/pkg/guacrest/helpers"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/handler/processor/guesser"
	"github.com/guacsec/guac/pkg/handler/processor/process"
	"github.com/guacsec/guac/pkg/logging"
)

// RetrieveSbom returns the HasSBOM record with the given ID, in the same
// shape the list endpoint returns as a SbomList item.
func RetrieveSbom(ctx context.Context, gqlClient graphql.Client, id string) (*gen.Sbom, error) {
	logger := logging.FromContext(ctx)

	response, err := gql.HasSBOMs(ctx, gqlClient, gql.HasSBOMSpec{Id: &id})
	if err != nil {
		// The ent backend compares the raw ID against a uuid column, so an ID
		// that is not a uuid fails in the database and comes back as a
		// resolver error. For a lookup by ID that means "no such SBOM".
		if isMalformedIDError(err) {
			return nil, helpers.Err404
		}
		logger.Errorf("HasSBOMs query returned error: %v", err)
		return nil, helpers.Err502
	}
	if response == nil {
		logger.Errorf("HasSBOMs query returned nil response")
		return nil, helpers.Err500
	}

	sboms := response.GetHasSBOM()
	switch len(sboms) {
	case 0:
		// The keyvalue backend returns an empty result for an unknown ID.
		return nil, helpers.Err404
	case 1:
	default:
		logger.Errorf("More than one HasSBOM was found with id %s", id)
		return nil, helpers.Err500
	}

	sbom, ok := sbomToREST(sboms[0])
	if !ok {
		logger.Warnf("HasSBOM %s has an unhandled subject type: %T", id, sboms[0].GetSubject())
		return nil, helpers.Err500
	}
	return &sbom, nil
}

// isMalformedIDError reports whether err is the GraphQL error the ent backend
// produces when the ID it was given is not a uuid.
func isMalformedIDError(err error) bool {
	var gqlErrors gqlerror.List
	if !errors.As(err, &gqlErrors) {
		return false
	}
	for _, gqlErr := range gqlErrors {
		if strings.Contains(gqlErr.Message, "invalid input syntax for type uuid") {
			return true
		}
	}
	return false
}

// SbomDocument contains the raw decompressed document content and HTTP header metadata.
type SbomDocument struct {
	Blob               []byte
	ContentType        string
	ContentDisposition string
}

// RetrieveSbomDocument retrieves the original SBOM document from the blob store
// associated with the given HasSBOM ID, decompressed according to its encoding.
func RetrieveSbomDocument(ctx context.Context, gqlClient graphql.Client, blobStore *blob.BlobStore, id string) (*SbomDocument, error) {
	logger := logging.FromContext(ctx)

	if blobStore == nil {
		return nil, helpers.Err503
	}

	response, err := gql.HasSBOMs(ctx, gqlClient, gql.HasSBOMSpec{Id: &id})
	if err != nil {
		if isMalformedIDError(err) {
			return nil, helpers.Err404
		}
		logger.Errorf("HasSBOMs query returned error: %v", err)
		return nil, helpers.Err502
	}
	if response == nil {
		logger.Errorf("HasSBOMs query returned nil response")
		return nil, helpers.Err500
	}

	sboms := response.GetHasSBOM()
	switch len(sboms) {
	case 0:
		return nil, helpers.Err404
	case 1:
	default:
		logger.Errorf("More than one HasSBOM was found with id %s", id)
		return nil, helpers.Err500
	}

	documentRef := sboms[0].GetDocumentRef()
	if documentRef == "" {
		return nil, helpers.Err404
	}

	blobBytes, err := blobStore.Read(ctx, documentRef)
	if err != nil {
		if gcerrors.Code(err) == gcerrors.NotFound {
			return nil, helpers.Err404
		}
		logger.Errorf("failed to read document from blob store: %v", err)
		return nil, helpers.Err500
	}

	var doc processor.Document
	if err := json.Unmarshal(blobBytes, &doc); err != nil {
		logger.Errorf("failed to unmarshal document from blob store: %v", err)
		return nil, helpers.Err500
	}

	if err := process.DecodeDocument(ctx, &doc); err != nil {
		logger.Errorf("failed to decode document: %v", err)
		return nil, helpers.Err500
	}

	format := doc.Format
	if format == "" || format == processor.FormatUnknown {
		if _, guessedFormat, err := guesser.GuessDocument(ctx, &doc); err == nil && guessedFormat != processor.FormatUnknown {
			format = guessedFormat
		}
	}

	var contentType, ext string
	switch format {
	case processor.FormatJSON:
		contentType = "application/json"
		ext = "json"
	case processor.FormatJSONLines:
		contentType = "application/x-ndjson"
		ext = "jsonl"
	case processor.FormatXML:
		contentType = "application/xml"
		ext = "xml"
	default:
		contentType = "application/octet-stream"
		ext = "bin"
	}

	contentDisposition := fmt.Sprintf("attachment; filename=\"%s.%s\"", documentRef, ext)

	return &SbomDocument{
		Blob:               doc.Blob,
		ContentType:        contentType,
		ContentDisposition: contentDisposition,
	}, nil
}
