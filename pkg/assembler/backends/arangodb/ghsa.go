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

func (c *arangoClient) Ghsa(ctx context.Context, ghsaSpec *model.GHSASpec) ([]*model.Ghsa, error) {
	values := map[string]any{}
	arangoQueryBuilder := newForQuery(ghsasStr, "ghsa")
	if ghsaSpec.ID != nil {
		arangoQueryBuilder.filter("ghsa", "_id", "==", "@id")
		values["id"] = *ghsaSpec.ID
	}
	if ghsaSpec.GhsaID != nil {
		arangoQueryBuilder.filter("ghsa", "ghsaId", "==", "@ghsaId")
		values["ghsaId"] = strings.ToLower(*ghsaSpec.GhsaID)
	}
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		"id": ghsa._id,
		"ghsaId": ghsa.ghsaId
	  }`)

	fmt.Println(arangoQueryBuilder.string())
	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "Ghsa")
	if err != nil {
		return nil, fmt.Errorf("failed to query for ghsa: %w", err)
	}
	defer cursor.Close()

	return getGHSAs(ctx, cursor)
}

func getGHSAQueryValues(ghsa *model.GHSAInputSpec) map[string]any {
	values := map[string]any{}
	values["ghsaId"] = strings.ToLower(ghsa.GhsaID)
	return values
}

func (c *arangoClient) IngestGHSAs(ctx context.Context, ghsas []*model.GHSAInputSpec) ([]*model.Ghsa, error) {
	var listOfValues []map[string]any
	for i := range ghsas {
		listOfValues = append(listOfValues, getGHSAQueryValues(ghsas[i]))
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
UPSERT { ghsaId:doc.ghsaId } 
INSERT { ghsaId:doc.ghsaId } 
UPDATE {} IN ghsas OPTIONS { indexHint: "byGhsaID" }
RETURN {
	"id": NEW._id,
	"ghsaId": NEW.ghsaId
  }`

	sb.WriteString(query)

	cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestGHSAs")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest ghsa: %w", err)
	}
	defer cursor.Close()

	return getGHSAs(ctx, cursor)
}

func (c *arangoClient) IngestGhsa(ctx context.Context, ghsa *model.GHSAInputSpec) (*model.Ghsa, error) {
	query := `
UPSERT { ghsaId:@ghsaId } 
INSERT { ghsaId:@ghsaId } 
UPDATE {} IN ghsas OPTIONS { indexHint: "byGhsaID" }
RETURN {
	"id": NEW._id,
	"ghsaId": NEW.ghsaId
  }`

	cursor, err := executeQueryWithRetry(ctx, c.db, query, getGHSAQueryValues(ghsa), "IngestGhsa")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest ghsa: %w", err)
	}
	defer cursor.Close()

	createdGHSAs, err := getGHSAs(ctx, cursor)
	if err != nil {
		return nil, fmt.Errorf("failed to get ghsas from arango cursor: %w", err)
	}
	if len(createdGHSAs) == 1 {
		return createdGHSAs[0], nil
	} else {
		return nil, fmt.Errorf("number of ghsas ingested is greater than one")
	}
}

func getGHSAs(ctx context.Context, cursor driver.Cursor) ([]*model.Ghsa, error) {
	var createdGHSAs []*model.Ghsa
	for {
		var doc *model.Ghsa
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to get ghsa from cursor: %w", err)
			}
		} else {
			createdGHSAs = append(createdGHSAs, doc)
		}
	}
	return createdGHSAs, nil
}
