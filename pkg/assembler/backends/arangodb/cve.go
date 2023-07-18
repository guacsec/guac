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

func (c *arangoClient) Cve(ctx context.Context, cveSpec *model.CVESpec) ([]*model.Cve, error) {
	values := map[string]any{}
	arangoQueryBuilder := newForQuery(cvesStr, "cve")
	if cveSpec.Year != nil {
		arangoQueryBuilder.filter("cve", "year", "==", "@year")
		values["year"] = *cveSpec.Year
	}
	if cveSpec.CveID != nil {
		arangoQueryBuilder.filter("cve", "cveId", "==", "@cveId")
		values["cveId"] = strings.ToLower(*cveSpec.CveID)
	}
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		"id": cve._id,
		"year": cve.year,
		"cveID": cve.cveId
	  }`)

	fmt.Println(arangoQueryBuilder.string())
	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "Cve")
	if err != nil {
		return nil, fmt.Errorf("failed to query for cve: %w", err)
	}
	defer cursor.Close()

	return getCVEs(ctx, cursor)
}

func getCVEQueryValues(cve *model.CVEInputSpec) map[string]any {
	values := map[string]any{}
	values["year"] = cve.Year
	values["cveId"] = strings.ToLower(cve.CveID)
	return values
}

func (c *arangoClient) IngestCVEs(ctx context.Context, cves []*model.CVEInputSpec) ([]*model.Cve, error) {
	listOfValues := []map[string]any{}
	for i := range cves {
		listOfValues = append(listOfValues, getCVEQueryValues(cves[i]))
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
UPSERT { year:doc.year, cveId:doc.cveId } 
INSERT { year:doc.year, cveId:doc.cveId } 
UPDATE {} IN cves OPTIONS { indexHint: "byCveID" }
RETURN NEW`

	sb.WriteString(query)

	cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestCVEs")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest cve: %w", err)
	}
	defer cursor.Close()

	return getCVEs(ctx, cursor)
}

func (c *arangoClient) IngestCve(ctx context.Context, cve *model.CVEInputSpec) (*model.Cve, error) {
	query := `
UPSERT { year:@year, cveId:@cveId } 
INSERT { year:@year, cveId:@cveId } 
UPDATE {} IN cves OPTIONS { indexHint: "byCveID" }
RETURN NEW`

	cursor, err := executeQueryWithRetry(ctx, c.db, query, getCVEQueryValues(cve), "IngestCve")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest cve: %w", err)
	}
	defer cursor.Close()

	createdCVEs, err := getCVEs(ctx, cursor)
	if err != nil {
		return nil, fmt.Errorf("failed to get cves from arango cursor: %w", err)
	}
	if len(createdCVEs) == 1 {
		return createdCVEs[0], nil
	} else {
		return nil, fmt.Errorf("number of cves ingested is greater than one")
	}
}

func getCVEs(ctx context.Context, cursor driver.Cursor) ([]*model.Cve, error) {
	var createdCVEs []*model.Cve
	for {
		var doc *model.Cve
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to get cve from cursor: %w", err)
			}
		} else {
			createdCVEs = append(createdCVEs, doc)
		}
	}
	return createdCVEs, nil
}
