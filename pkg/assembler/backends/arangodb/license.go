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
	"fmt"
	"slices"
	"strings"

	"github.com/arangodb/go-driver"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (c *arangoClient) Licenses(ctx context.Context, licenseSpec *model.LicenseSpec) ([]*model.License, error) {
	values := map[string]any{}
	aqb := setLicenseMatchValues(licenseSpec, values)
	aqb.query.WriteString("\n")
	aqb.query.WriteString(`RETURN {
  "id": license._id,
  "name": license.name,
  "inline": license.inline,
  "listversion": license.listversion,
}`)

	cursor, err := executeQueryWithRetry(ctx, c.db, aqb.string(), values, "Licenses")
	if err != nil {
		return nil, fmt.Errorf("failed to query for license: %w", err)
	}
	defer cursor.Close()

	return getLicenses(ctx, cursor)
}

func setLicenseMatchValues(licenseSpec *model.LicenseSpec, queryValues map[string]any) *arangoQueryBuilder {
	aqb := newForQuery(licensesStr, "license")
	if licenseSpec != nil {
		if licenseSpec.ID != nil {
			aqb.filter("license", "_id", "==", "@id")
			queryValues["id"] = *licenseSpec.ID
		}
		if licenseSpec.Name != nil {
			aqb.filter("license", "name", "==", "@name")
			queryValues["name"] = *licenseSpec.Name
		}
		if licenseSpec.Inline != nil {
			aqb.filter("license", "inline", "==", "@inline")
			queryValues["inline"] = *licenseSpec.Inline
		}
		if licenseSpec.ListVersion != nil {
			aqb.filter("license", "listversion", "==", "@listversion")
			queryValues["listversion"] = *licenseSpec.ListVersion
		}
	}
	return aqb
}

func getLicenseQueryValues(license *model.LicenseInputSpec) map[string]any {
	values := map[string]any{}
	values["name"] = license.Name
	values["inline"] = nilToEmpty(license.Inline)
	values["listversion"] = nilToEmpty(license.ListVersion)
	return values
}

func nilToEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (c *arangoClient) IngestLicenses(ctx context.Context, licenses []*model.LicenseInputSpec) ([]*model.License, error) {

	var listOfValues []map[string]any

	for i := range licenses {
		listOfValues = append(listOfValues, getLicenseQueryValues(licenses[i]))
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
UPSERT { name:doc.name, inline:doc.inline, listversion:doc.listversion }
INSERT { name:doc.name, inline:doc.inline, listversion:doc.listversion }
UPDATE {} IN licenses OPTIONS { indexHint: "byNameInlineListVer" }
RETURN {
  "id": NEW._id,
  "name": NEW.name,
  "inline": NEW.inline,
  "listversion": NEW.listversion,
}`

	sb.WriteString(query)

	cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestLicenses")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest license: %w", err)
	}
	defer cursor.Close()

	return getLicenses(ctx, cursor)

}

func (c *arangoClient) IngestLicense(ctx context.Context, license *model.LicenseInputSpec) (*model.License, error) {
	query := `
UPSERT { name:@name, inline:@inline, listversion:@listversion }
INSERT { name:@name, inline:@inline, listversion:@listversion }
UPDATE {} IN licenses OPTIONS { indexHint: "byNameInlineListVer" }
RETURN {
  "id": NEW._id,
  "name": NEW.name,
  "inline": NEW.inline,
  "listversion": NEW.listversion,
}`

	cursor, err := executeQueryWithRetry(ctx, c.db, query, getLicenseQueryValues(license), "IngestLicense")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest license: %w", err)
	}
	defer cursor.Close()

	createdLicenses, err := getLicenses(ctx, cursor)
	if err != nil {
		return nil, fmt.Errorf("failed to get licenses from arango cursor: %w", err)
	}
	if len(createdLicenses) == 1 {
		return createdLicenses[0], nil
	} else {
		return nil, fmt.Errorf("number of licenses ingested is greater than one")
	}
}

func getLicenses(ctx context.Context, cursor driver.Cursor) ([]*model.License, error) {
	var createdLicenses []*model.License
	for {
		var doc *model.License
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to get license from cursor: %w", err)
			}
		} else {
			if *doc.Inline == "" {
				doc.Inline = nil
			}
			if *doc.ListVersion == "" {
				doc.ListVersion = nil
			}
			createdLicenses = append(createdLicenses, doc)
		}
	}
	return createdLicenses, nil
}

func (c *arangoClient) getLicenses(ctx context.Context, licenses []*model.LicenseInputSpec) ([]*model.License, error) {
	var listOfValues []map[string]any
	for i := range licenses {
		listOfValues = append(listOfValues, getLicenseQueryValues(licenses[i]))
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
	sb.WriteString("\n")

	arangoQueryBuilder := newForQuery(licensesStr, "lic")
	arangoQueryBuilder.filter("lic", "name", "==", "doc.name")
	arangoQueryBuilder.filter("lic", "inline", "==", "doc.inline")
	arangoQueryBuilder.filter("lic", "listversion", "==", "doc.listversion")
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		"id": lic._id,
		"name": lic.name,
		"inline": lic.inline,
		"listversion": lic.listversion
	  }`)

	sb.WriteString(arangoQueryBuilder.string())

	cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "getMaterials")
	if err != nil {
		return nil, fmt.Errorf("failed to query for Licenses: %w", err)
	}
	defer cursor.Close()

	return getLicenses(ctx, cursor)
}

func (c *arangoClient) getLicensesByID(ctx context.Context, licIDs []string) ([]*model.License, error) {
	var listOfValues []map[string]any
	for _, id := range licIDs {
		values := map[string]any{}
		values["id"] = id
		listOfValues = append(listOfValues, values)
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
	sb.WriteString("\n")

	arangoQueryBuilder := newForQuery(licensesStr, "lic")
	arangoQueryBuilder.filter("lic", "_id", "==", "doc.id")
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		"id": lic._id,
		"name": lic.name,
		"inline": lic.inline,
		"listversion": lic.listversion
	  }`)

	sb.WriteString(arangoQueryBuilder.string())

	cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "getLicensesByID")
	if err != nil {
		return nil, fmt.Errorf("failed to query for Licenses: %w", err)
	}
	defer cursor.Close()

	return getLicenses(ctx, cursor)
}

func (c *arangoClient) getLicenseByID(ctx context.Context, licID string) (*model.License, error) {
	licenses, err := c.getLicensesByID(ctx, []string{licID})
	if err != nil {
		return nil, fmt.Errorf("failed to get license by ID for: %s, with error: %w", licID, err)
	}
	if len(licenses) != 1 {
		return nil, fmt.Errorf("number of license nodes found for ID: %s is greater than one", licID)
	}
	return licenses[0], nil
}

func licenseMatch(filters []*model.LicenseSpec, values []*model.License) bool {
	left := slices.Clone(values)

	for _, f := range filters {
		found := false
		for i, v := range left {
			if f.ID != nil && *f.ID == v.ID {
				found = true
				left = slices.Delete(left, i, i+1)
				break
			}
			if (f.Name == nil || *f.Name == v.Name) &&
				(f.Inline == nil || (v.Inline != nil && *f.Inline == *v.Inline)) &&
				(f.ListVersion == nil || (v.ListVersion != nil && *f.ListVersion == *v.ListVersion)) {
				found = true
				left = slices.Delete(left, i, i+1)
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (c *arangoClient) licenseNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]string, error) {
	out := []string{}

	if allowedEdges[model.EdgeLicenseCertifyLegal] {
		// certifyLegalDeclaredLicensesEdges
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(licensesStr, "lic")
		arangoQueryBuilder.filter("lic", "_id", "==", "@id")
		values["id"] = nodeID
		arangoQueryBuilder.forInBound(certifyLegalDeclaredLicensesEdgesStr, "certifyLegal", "lic")
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor: certifyLegal._id }")

		foundDeclaredIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "licenseNeighbors")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundDeclaredIDs...)

		// certifyLegalDiscoveredLicensesEdges

		values = map[string]any{}
		arangoQueryBuilder = newForQuery(licensesStr, "lic")
		arangoQueryBuilder.filter("lic", "_id", "==", "@id")
		values["id"] = nodeID
		arangoQueryBuilder.forInBound(certifyLegalDiscoveredLicensesEdgesStr, "certifyLegal", "lic")
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor: certifyLegal._id }")

		foundDiscoveredLicenseIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "licenseNeighbors")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundDiscoveredLicenseIDs...)
	}

	return out, nil
}
