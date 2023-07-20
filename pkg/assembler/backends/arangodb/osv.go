//
// Copyright 2023 The GUAC Authors.
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

package arangodb

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/arangodb/go-driver"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (c *arangoClient) Osv(ctx context.Context, osvSpec *model.OSVSpec) ([]*model.Osv, error) {
	values := map[string]any{}
	arangoQueryBuilder := newForQuery(osvsStr, "osv")
	if osvSpec.OsvID != nil {
		arangoQueryBuilder.filter("osv", "osvId", "==", "@osvId")
		values["osvId"] = strings.ToLower(*osvSpec.OsvID)
	}
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		"id": osv._id,
		"osvId": osv.osvId
	  }`)

	fmt.Println(arangoQueryBuilder.string())
	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "Osv")
	if err != nil {
		return nil, fmt.Errorf("failed to query for osv: %w", err)
	}
	defer cursor.Close()

	return getOSVs(ctx, cursor)
}

func getOSVQueryValues(osv *model.OSVInputSpec) map[string]any {
	values := map[string]any{}
	values["osvId"] = strings.ToLower(osv.OsvID)
	return values
}

func (c *arangoClient) IngestOSVs(ctx context.Context, osvs []*model.OSVInputSpec) ([]*model.Osv, error) {
	var listOfValues []map[string]any
	for i := range osvs {
		listOfValues = append(listOfValues, getOSVQueryValues(osvs[i]))
	}

	var documents []string
	for _, val := range listOfValues {
		bs, _ := json.Marshal(val)
		documents = append(documents, string(bs))
	}

	queryValues := map[string]any{}
	queryValues["documents"] = fmt.Sprint(strings.Join(documents, ","))

	var sb strings.Builder

	sb.WriteString("for doc in [")
	for i, val := range listOfValues {
		bs, _ := json.Marshal(val)
		if i == len(listOfValues)-1 {
			sb.WriteString(string(bs))
		} else {
			sb.WriteString(string(bs) + ",")
		}
	}
	sb.WriteString("]")

	query := `
UPSERT { osvId:doc.osvId } 
INSERT { osvId:doc.osvId } 
UPDATE {} IN osvs OPTIONS { indexHint: "byOsvID" }
RETURN {
	"id": NEW._id,
	"osvId": NEW.osvId
  }`

	sb.WriteString(query)

	cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestOSVs")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest osv: %w", err)
	}
	defer cursor.Close()

	return getOSVs(ctx, cursor)
}

func (c *arangoClient) IngestOsv(ctx context.Context, osv *model.OSVInputSpec) (*model.Osv, error) {
	query := `
UPSERT { osvId:@osvId } 
INSERT { osvId:@osvId } 
UPDATE {} IN osvs OPTIONS { indexHint: "byOsvID" }
RETURN {
	"id": NEW._id,
	"osvId": NEW.osvId
  }`

	cursor, err := executeQueryWithRetry(ctx, c.db, query, getOSVQueryValues(osv), "IngestOsv")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest osv: %w", err)
	}
	defer cursor.Close()

	createdOSVs, err := getOSVs(ctx, cursor)
	if err != nil {
		return nil, fmt.Errorf("failed to get osvs from arango cursor: %w", err)
	}
	if len(createdOSVs) == 1 {
		return createdOSVs[0], nil
	} else {
		return nil, fmt.Errorf("number of osvs ingested is greater than one")
	}
}

func getOSVs(ctx context.Context, cursor driver.Cursor) ([]*model.Osv, error) {
	var createdOSVs []*model.Osv
	for {
		var doc *model.Osv
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to get ghsa from cursor: %w", err)
			}
		} else {
			createdOSVs = append(createdOSVs, doc)
		}
	}
	return createdOSVs, nil
}
